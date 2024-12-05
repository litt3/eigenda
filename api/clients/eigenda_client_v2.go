package clients

import (
	"context"
	auth "github.com/Layr-Labs/eigenda/core/auth/v2"
	"github.com/Layr-Labs/eigenda/encoding"
	"github.com/Layr-Labs/eigenda/encoding/kzg"
	"github.com/Layr-Labs/eigenda/encoding/kzg/prover"
	"github.com/Layr-Labs/eigensdk-go/logging"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/hashicorp/go-multierror"
	"math/rand"
	"net"
	"time"

	"fmt"
	"github.com/Layr-Labs/eigenda/api"
	"github.com/Layr-Labs/eigenda/api/clients/codecs"
	eigendacommon "github.com/Layr-Labs/eigenda/api/grpc/common"
	grpcdisperserv2 "github.com/Layr-Labs/eigenda/api/grpc/disperser/v2"
	edasm "github.com/Layr-Labs/eigenda/contracts/bindings/EigenDAServiceManager"
	corev2 "github.com/Layr-Labs/eigenda/core/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

// EigenDAClientV2 provides the ability to get blobs from the relay subsystem, and to send new blobs to the disperser.
type EigenDAClientV2 interface {
	GetBlob(ctx context.Context, blobKey corev2.BlobKey, blobCertificate corev2.BlobCertificate) ([]byte, error)
	PutBlob(ctx context.Context, rawBytes []byte, blobVersion corev2.BlobVersion) (*eigendacommon.BlobCommitment, error)
	GetCodec() codecs.BlobCodec
	Close() error
}

// See the NewEigenDAClientV2 constructor's documentation for details and usage examples.
type eigenDAClientV2 struct {
	clientConfig    EigenDAClientConfig
	log             logging.Logger
	disperserClient DisperserClientV2
	relayClient     RelayClient
	ethClient       *ethclient.Client
	edasmCaller     *edasm.ContractEigenDAServiceManagerCaller
	codec           codecs.BlobCodec
}

var _ EigenDAClientV2 = &eigenDAClientV2{}

// NewEigenDAClientV2 constructs an EigenDAClientV2 object, which provides the ability to get blobs from the relay
// subsystem, and to send new blobs to the disperser.
//
// Example usage:
//
//	client, err := NewEigenDAClientV2(log, EigenDAClientConfig{...}, kzg.KzgConfig{...}, RelayClientConfig{...})
//	if err != nil {
//	  return err
//	}
//	defer client.Close()
//
//	blobData := []byte("hello world")
//	blobInfo, err := client.PutBlob(ctx, blobData, 0)
//	if err != nil {
//	  return err
//	}
//
//	retrievedData, err := client.GetBlob(ctx, v2.BlobKey, blobCertificate v2.BlobCertificate)
//	if err != nil {
//	  return err
//	}
func NewEigenDAClientV2(
	log logging.Logger,
	clientConfig EigenDAClientConfig,
	kzgConfig kzg.KzgConfig,
	encodingConfig encoding.Config,
	relayClientConfig RelayClientConfig) (EigenDAClientV2, error) {

	err := clientConfig.CheckAndSetDefaults()
	if err != nil {
		return nil, err
	}

	hostname, port, err := net.SplitHostPort(clientConfig.RPC)
	if err != nil {
		return nil, fmt.Errorf("parse EigenDA RPC: %w", err)
	}
	disperserConfig := &DisperserClientV2Config{
		Hostname: hostname,
		Port:     port,
		// TODO: where should we get this value from?
		UseSecureGrpcFlag: true,
	}

	var signer corev2.BlobRequestSigner
	if len(clientConfig.SignerPrivateKeyHex) == 64 {
		signer = auth.NewLocalBlobRequestSigner(clientConfig.SignerPrivateKeyHex)
	} else if len(clientConfig.SignerPrivateKeyHex) == 0 {
		// noop signer is used when we need a read-only eigenda client
		signer = auth.NewLocalNoopSigner()
	} else {
		return nil, fmt.Errorf("invalid length for signer private key")
	}

	encodingProver, err := prover.NewProver(&kzgConfig, &encodingConfig)
	if err != nil {
		return nil, fmt.Errorf("new prover: %w", err)
	}
	disperserClient, err := NewDisperserClientV2(disperserConfig, signer, encodingProver)
	if err != nil {
		return nil, fmt.Errorf("new disperser-client: %w", err)
	}

	relayClient, err := NewRelayClient(&relayClientConfig, log)

	var ethClient *ethclient.Client
	ethClient, err = ethclient.Dial(clientConfig.EthRpcUrl)
	if err != nil {
		return nil, fmt.Errorf("dial ETH RPC node: %w", err)
	}

	var edasmCaller *edasm.ContractEigenDAServiceManagerCaller
	edasmCaller, err = edasm.NewContractEigenDAServiceManagerCaller(common.HexToAddress(clientConfig.SvcManagerAddr), ethClient)
	if err != nil {
		return nil, fmt.Errorf("new NewContractEigenDAServiceManagerCaller: %w", err)
	}

	lowLevelCodec, err := codecs.BlobEncodingVersionToCodec(clientConfig.PutBlobEncodingVersion)
	if err != nil {
		return nil, fmt.Errorf("create low level codec: %w", err)
	}
	var codec codecs.BlobCodec
	if clientConfig.DisablePointVerificationMode {
		codec = codecs.NewNoIFFTCodec(lowLevelCodec)
	} else {
		codec = codecs.NewIFFTCodec(lowLevelCodec)
	}

	return &eigenDAClientV2{
		clientConfig:    clientConfig,
		log:             log,
		disperserClient: disperserClient,
		relayClient:     relayClient,
		ethClient:       ethClient,
		edasmCaller:     edasmCaller,
		codec:           codec,
	}, nil
}

// GetBlob retrieves a blob using the provided context, blob key, and blob certificate.
//
// This function iteratively attempts to retrieve the blob from the array of relays
// contained in the blob certificate in random order, until the blob is retrieved successfully.
//
// The returned blob is decoded.
func (c *eigenDAClientV2) GetBlob(ctx context.Context, blobKey corev2.BlobKey, blobCertificate corev2.BlobCertificate) ([]byte, error) {
	// create a randomized array of indices, so that it isn't always the first relay in the list which gets hit
	random := rand.New(rand.NewSource(rand.Int63()))
	relayKeyCount := len(blobCertificate.RelayKeys)
	var indices []int
	for i := 0; i < relayKeyCount; i++ {
		indices = append(indices, i)
	}
	random.Shuffle(len(indices), func(i int, j int) {
		indices[i], indices[j] = indices[j], indices[i]
	})

	// TODO (litt3): consider creating a utility which can deprioritize relays that fail to respond (or respond maliciously)

	// iterate over relays in random order, until we are able to get the blob from someone
	for i := range indices {
		relayKey := blobCertificate.RelayKeys[i]
		var err error
		data, err := c.relayClient.GetBlob(ctx, relayKey, blobKey)

		// if GetBlob returned an error, try calling a different relay
		if err != nil {
			// TODO: should this log type be downgraded to debug to avoid log spam? I'm not sure how frequent retrieval
			//  from a relay will fail in practice (?)
			c.log.Info("blob couldn't be retrieved from relay", "blobKey", blobKey, "relayKey", relayKey)
			continue
		}

		// An honest relay should never send an empty blob
		// https://github.com/Layr-Labs/eigenda/blob/master/disperser/apiserver/server.go#L930
		if len(data) == 0 {
			c.log.Warn("blob received from relay had length 0", "blobKey", blobKey, "relayKey", relayKey)
			continue
		}

		// An honest relay should never send a blob which cannot be decoded
		decodedData, err := c.codec.DecodeBlob(data)
		if err != nil {
			c.log.Warn("error decoding blob", "blobKey", blobKey, "relayKey", relayKey)
			continue
		}

		return decodedData, nil
	}

	return nil, fmt.Errorf("unable to retrieve blob from any relay")
}

// PutBlob encodes and writes a blob to EigenDA, waiting for the blob to be certified before fetching and returning the
// blob commitment.
//
// After submitting a blob to the disperser, this method will periodically poll the disperser for the status of the
// dispersal. This polling continues until a status indicating success or failure is received, or until the configured
// clientConfig.StatusQueryTimeout has elapsed.
//
// If a blob status is received indicating successful dispersal, this method will make an additional call to the
// disperser, to fetch and return the blob commitment.
func (c *eigenDAClientV2) PutBlob(
	ctx context.Context,
	rawData []byte,
	blobVersion corev2.BlobVersion) (*eigendacommon.BlobCommitment, error) {

	c.log.Info("Attempting to disperse blob to EigenDA")

	encodedData, err := c.getEncodedBlob(rawData)
	if err != nil {
		return nil, err
	}

	customQuorumNumbers := make([]uint8, len(c.clientConfig.CustomQuorumIDs))
	for i, e := range c.clientConfig.CustomQuorumIDs {
		customQuorumNumbers[i] = uint8(e)
	}

	blobStatus, blobKey, err := c.disperserClient.DisperseBlob(ctx, encodedData, blobVersion, customQuorumNumbers)

	if err != nil {
		// DisperserClient returned error is already a grpc error which can be a 400 (e.g. rate limited) or 500,
		// so we wrap the error such that clients can still use grpc's status.FromError() function to get the status code.
		return nil, fmt.Errorf("error submitting blob to disperser: %w", err)
	}

	blobStatusHandler := &blobStatusHandler{}
	blobCertified, err := blobStatusHandler.handleStatus(blobKey, blobStatus.ToProfobuf())
	if err != nil {
		return nil, err
	} else if !blobCertified {
		// continuously poll, until the blob is either certified, fails, or we time out
		err = c.pollBlobPutStatus(ctx, blobKey, blobStatusHandler)
		if err != nil {
			return nil, err
		}
	}

	// we will only arrive here if the blob status was returned as CERTIFIED
	return c.fetchCommitment(ctx, rawData)
}

// fetchCommitment attempts to get the blob commitment from the disperser client
// The raw data passed into this method is FFTed prior to being passed as an argument to GetBlobCommitment.
func (c *eigenDAClientV2) fetchCommitment(ctx context.Context, rawData []byte) (*eigendacommon.BlobCommitment, error) {
	fftdBlob, err := codecs.FFT(rawData)
	if err != nil {
		return nil, err
	}

	commitmentReply, err := c.disperserClient.GetBlobCommitment(ctx, fftdBlob)
	if err != nil {
		return nil, err
	}

	return commitmentReply.GetBlobCommitment(), nil
}

// pollBlobPutStatus repeatedly submits GetBlobStatus queries to the disperser every clientConfig.StatusQueryRetryInterval,
// until one of the following conditions becomes true:
// 1. A status is returned which indicates that the PUT was unsuccessful
// 2. A CERTIFIED status is returned, which indicates that the PUT was successful
// 3. The configured clientConfig.StatusQueryTimeout is reached
func (c *eigenDAClientV2) pollBlobPutStatus(
	ctx context.Context,
	blobKey corev2.BlobKey,
	blobStatusHandler *blobStatusHandler) error {

	c.log.Info("Blob accepted by EigenDA disperser, now polling for status updates", "blobKey", blobKey)

	ticker := time.NewTicker(c.clientConfig.StatusQueryRetryInterval)
	defer ticker.Stop()

	var cancel context.CancelFunc
	// TODO: is StatusQueryTimeout the correct value to be used here?
	ctx, cancel = context.WithTimeout(ctx, c.clientConfig.StatusQueryTimeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			switch blobStatusHandler.getStatus() {
			case grpcdisperserv2.BlobStatus_QUEUED:
				return api.NewErrorFailover(fmt.Errorf(
					"timed out waiting for blob (blobKey=%v) to be encoded by the disperser", blobKey))
			case grpcdisperserv2.BlobStatus_ENCODED:
				return api.NewErrorFailover(fmt.Errorf(
					"timed out waiting for blob (blobKey=%v) to be dispersed and attested by the DA nodes ",
					blobKey))
			default:
				return api.NewErrorInternal(fmt.Sprintf(
					"unexpected BlobStatus \"%v\" for blob %v. It should not be possible to reach this statement.",
					blobStatusHandler.getStatus(), blobKey))
			}
		case <-ticker.C:
			blobStatusReply, err := c.disperserClient.GetBlobStatus(ctx, blobKey)
			if err != nil {
				c.log.Warn("Unable to retrieve blob dispersal status, will retry",
					"blobKey", blobKey, "err", err)
				continue
			}

			blobCertified, err := blobStatusHandler.handleStatus(blobKey, blobStatusReply.Status)
			if err != nil {
				return err
			} else if blobCertified {
				return nil
			} else {
				continue
			}
		}
	}
}

// getEncodedBlob uses the codec to encode the raw blob data, and returns the encoded data
func (c *eigenDAClientV2) getEncodedBlob(rawData []byte) ([]byte, error) {
	if c.codec == nil {
		return nil, api.NewErrorInternal("codec not initialized")
	}

	encodedData, err := c.codec.EncodeBlob(rawData)
	if err != nil {
		// Encode can only fail if there is something wrong with the data, so we return a 400 error
		return nil, api.NewErrorInvalidArg(fmt.Sprintf("error encoding blob: %v", err))
	}

	return encodedData, nil
}

func (c *eigenDAClientV2) GetCodec() codecs.BlobCodec {
	return c.codec
}

func (c *eigenDAClientV2) Close() error {
	c.ethClient.Close()

	var errList *multierror.Error

	relayClientErr := c.relayClient.Close()
	if relayClientErr != nil {
		errList = multierror.Append(errList, relayClientErr)
	}

	disperserClientErr := c.disperserClient.Close()
	if disperserClientErr != nil {
		errList = multierror.Append(errList, disperserClientErr)
	}

	if errList != nil {
		return errList.ErrorOrNil()
	}

	return nil
}

// blobStatusHandler keeps track of the current blob status while the client is waiting for a blob to be fully dispersed
// and certified. It is responsible for recording logs as status query responses are received from the disperser, and
// for raising an error if transitioning to a failure state.
type blobStatusHandler struct {
	status grpcdisperserv2.BlobStatus
}

func (h *blobStatusHandler) getStatus() grpcdisperserv2.BlobStatus {
	return h.status
}

// handleStatus accepts a new status received from the disperser, and writes relevant logs.
// This method returns true if the blob status transitioned to CERTIFIED, which indicates that the dispersal was successful
func (h *blobStatusHandler) handleStatus(
	blobKey corev2.BlobKey,
	newStatus grpcdisperserv2.BlobStatus) (bool, error) {

	switch newStatus {
	case grpcdisperserv2.BlobStatus_QUEUED:
		message := fmt.Sprintf("blob (blobKey=%v) has been queued by the disperser for processing", blobKey)
		if newStatus != h.status {
			log.Info(message)
		} else {
			log.Debug(message)
		}
		return false, nil
	case grpcdisperserv2.BlobStatus_ENCODED:
		message := fmt.Sprintf("blob (blobKey=%v) has been encoded and is ready to be dispersed to DA Nodes", blobKey)
		if newStatus != h.status {
			log.Info(message)
		} else {
			log.Debug(message)
		}
		return false, nil
	case grpcdisperserv2.BlobStatus_CERTIFIED:
		log.Info(fmt.Sprintf("blob (blobKey=%v) has been dispersed and attested by the DA nodes", blobKey))

		return true, nil
	case grpcdisperserv2.BlobStatus_FAILED:
		return false, api.NewErrorInternal(fmt.Sprintf(
			"blob dispersal (blobKey=%v) reached failed status. please resubmit the blob.", blobKey))
	case grpcdisperserv2.BlobStatus_INSUFFICIENT_SIGNATURES:
		// Some quorum failed to sign the blob, indicating that the whole network is having issues.
		// We hence return api.ErrorFailover to let the batcher failover to ethDA. This could however be a very unlucky
		// temporary issue, so the caller should retry at least one more time before failing over.
		return false, api.NewErrorFailover(fmt.Errorf(
			"blob dispersal (blobKey=%v) failed with insufficient signatures: eigenDA nodes are probably down", blobKey))
	default:
		return false, api.NewErrorInternal(fmt.Sprintf("invalid BlobStatus for blob %v", blobKey))
	}
}

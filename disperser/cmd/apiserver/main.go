package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Layr-Labs/eigenda/common"
	"github.com/Layr-Labs/eigenda/disperser/apiserver"
	"github.com/Layr-Labs/eigenda/disperser/common/blobstore"
	mt "github.com/Layr-Labs/eigenda/disperser/meterer"
	"github.com/Layr-Labs/eigenda/encoding/fft"
	"github.com/Layr-Labs/eigensdk-go/logging"
	"github.com/prometheus/client_golang/prometheus"

	commonaws "github.com/Layr-Labs/eigenda/common/aws"
	"github.com/Layr-Labs/eigenda/common/aws/dynamodb"
	"github.com/Layr-Labs/eigenda/common/aws/s3"
	"github.com/Layr-Labs/eigenda/common/geth"
	"github.com/Layr-Labs/eigenda/common/ratelimit"
	"github.com/Layr-Labs/eigenda/common/store"
	"github.com/Layr-Labs/eigenda/core/eth"
	"github.com/Layr-Labs/eigenda/disperser"
	"github.com/Layr-Labs/eigenda/disperser/cmd/apiserver/flags"
	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/urfave/cli"
)

var (
	// version is the version of the binary.
	version   string
	gitCommit string
	gitDate   string
)

func main() {
	app := cli.NewApp()
	app.Flags = flags.Flags
	app.Version = fmt.Sprintf("%s-%s-%s", version, gitCommit, gitDate)
	app.Name = "disperser"
	app.Usage = "EigenDA Disperser Server"
	app.Description = "Service for accepting blobs for dispersal"

	app.Action = RunDisperserServer
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("application failed: %v", err)
	}

	select {}
}

func RunDisperserServer(ctx *cli.Context) error {
	config, err := NewConfig(ctx)
	if err != nil {
		return err
	}

	logger, err := common.NewLogger(config.LoggerConfig)
	if err != nil {
		return err
	}
	client, err := geth.NewMultiHomingClient(config.EthClientConfig, gethcommon.Address{}, logger)
	if err != nil {
		logger.Error("Cannot create chain.Client", "err", err)
		return err
	}

	transactor, err := eth.NewTransactor(logger, client, config.BLSOperatorStateRetrieverAddr, config.EigenDAServiceManagerAddr)
	if err != nil {
		return err
	}
	blockStaleMeasure, err := transactor.GetBlockStaleMeasure(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get BLOCK_STALE_MEASURE: %w", err)
	}
	storeDurationBlocks, err := transactor.GetStoreDurationBlocks(context.Background())
	if err != nil || storeDurationBlocks == 0 {
		return fmt.Errorf("failed to get STORE_DURATION_BLOCKS: %w", err)
	}

	s3Client, err := s3.NewClient(context.Background(), config.AwsClientConfig, logger)
	if err != nil {
		return err
	}

	dynamoClient, err := dynamodb.NewClient(config.AwsClientConfig, logger)
	if err != nil {
		return err
	}

	bucketName := config.BlobstoreConfig.BucketName
	logger.Info("Creating blob store", "bucket", bucketName)
	blobMetadataStore := blobstore.NewBlobMetadataStore(dynamoClient, logger, config.BlobstoreConfig.TableName, config.BlobstoreConfig.ShadowTableName, time.Duration((storeDurationBlocks+blockStaleMeasure)*12)*time.Second)
	blobStore := blobstore.NewSharedStorage(bucketName, s3Client, blobMetadataStore, logger)

	reg := prometheus.NewRegistry()

	var meterer *mt.Meterer
	if config.EnablePaymentMeterer {
		config := mt.Config{
			PricePerChargeable:   config.PricePerChargeable,
			GlobalBytesPerSecond: config.OnDemandGlobalLimit,
			MinChargeableSize:    config.MinChargeableSize,
			ReservationWindow:    time.Minute,
		}

		paymentChainState := mt.NewMockedOnchainPaymentState()

		paymentChainState.InitializeOnchainPaymentState()

		clientConfig := commonaws.ClientConfig{
			Region:          "us-east-1",
			AccessKey:       "localstack",
			SecretAccessKey: "localstack",
			EndpointURL:     fmt.Sprintf("http://0.0.0.0:4566"),
		}

		store, err := mt.NewOffchainStore(
			clientConfig,
			"reservations",
			"ondemand",
			"global",
			logger,
		)
		if err != nil {
			return fmt.Errorf("failed to create offchain store: %w", err)
		}
		// add some default sensible configs
		meterer, err = mt.NewMeterer(
			config,
			mt.TimeoutConfig{},
			paymentChainState,
			store,
			logging.NewNoopLogger(),
			// metrics.NewNoopMetrics(),
		)
		if err != nil {
			return fmt.Errorf("failed to create meterer: %w", err)
		}
	}

	var ratelimiter common.RateLimiter
	if config.EnableRatelimiter {
		globalParams := config.RatelimiterConfig.GlobalRateParams

		var bucketStore common.KVStore[common.RateBucketParams]
		if config.BucketTableName != "" {
			dynamoClient, err := dynamodb.NewClient(config.AwsClientConfig, logger)
			if err != nil {
				return err
			}
			bucketStore = store.NewDynamoParamStore[common.RateBucketParams](dynamoClient, config.BucketTableName)
		} else {
			bucketStore, err = store.NewLocalParamStore[common.RateBucketParams](config.BucketStoreSize)
			if err != nil {
				return err
			}
		}
		ratelimiter = ratelimit.NewRateLimiter(reg, globalParams, bucketStore, logger)
	}

	if config.MaxBlobSize <= 0 || config.MaxBlobSize > 32*1024*1024 {
		return fmt.Errorf("configured max blob size is invalid %v", config.MaxBlobSize)
	}

	if !fft.IsPowerOfTwo(uint64(config.MaxBlobSize)) {
		return fmt.Errorf("configured max blob size must be power of 2 %v", config.MaxBlobSize)
	}

	metrics := disperser.NewMetrics(reg, config.MetricsConfig.HTTPPort, logger)
	server := apiserver.NewDispersalServer(
		config.ServerConfig,
		blobStore,
		transactor,
		logger,
		metrics,
		meterer,
		ratelimiter,
		config.RateConfig,
		config.MaxBlobSize,
	)

	// Enable Metrics Block
	if config.MetricsConfig.EnableMetrics {
		httpSocket := fmt.Sprintf(":%s", config.MetricsConfig.HTTPPort)
		metrics.Start(context.Background())
		logger.Info("Enabled metrics for Disperser", "socket", httpSocket)
	}

	return server.Start(context.Background())
}

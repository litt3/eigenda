package meterer

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	pb "github.com/Layr-Labs/eigenda/api/grpc/disperser/v2"
	commonaws "github.com/Layr-Labs/eigenda/common/aws"
	commondynamodb "github.com/Layr-Labs/eigenda/common/aws/dynamodb"
	"github.com/Layr-Labs/eigenda/core"
	"github.com/Layr-Labs/eigensdk-go/logging"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const MinNumBins int32 = 3

type OffchainStore struct {
	dynamoClient         commondynamodb.Client
	reservationTableName string
	onDemandTableName    string
	globalBinTableName   string
	logger               logging.Logger
	// TODO: add maximum storage for both tables
}

func NewOffchainStore(
	cfg commonaws.ClientConfig,
	reservationTableName string,
	onDemandTableName string,
	globalBinTableName string,
	logger logging.Logger,
) (OffchainStore, error) {

	dynamoClient, err := commondynamodb.NewClient(cfg, logger)
	if err != nil {
		return OffchainStore{}, err
	}

	err = dynamoClient.TableExists(context.Background(), reservationTableName)
	if err != nil {
		return OffchainStore{}, err
	}
	err = dynamoClient.TableExists(context.Background(), onDemandTableName)
	if err != nil {
		return OffchainStore{}, err
	}
	err = dynamoClient.TableExists(context.Background(), globalBinTableName)
	if err != nil {
		return OffchainStore{}, err
	}
	//TODO: add a separate thread to periodically clean up the tables
	// delete expired reservation bins (<i-1) and old on-demand payments (retain max N payments)
	return OffchainStore{
		dynamoClient:         dynamoClient,
		reservationTableName: reservationTableName,
		onDemandTableName:    onDemandTableName,
		globalBinTableName:   globalBinTableName,
		logger:               logger,
	}, nil
}

type ReservationBin struct {
	AccountID string
	BinIndex  uint32
	BinUsage  uint32
	UpdatedAt time.Time
}

type PaymentTuple struct {
	CumulativePayment uint64
	DataLength        uint32
}

type GlobalBin struct {
	BinIndex  uint32
	BinUsage  uint64
	UpdatedAt time.Time
}

func (s *OffchainStore) UpdateReservationBin(ctx context.Context, accountID string, binIndex uint64, size uint64) (uint64, error) {
	key := map[string]types.AttributeValue{
		"AccountID": &types.AttributeValueMemberS{Value: accountID},
		"BinIndex":  &types.AttributeValueMemberN{Value: strconv.FormatUint(binIndex, 10)},
	}

	res, err := s.dynamoClient.IncrementBy(ctx, s.reservationTableName, key, "BinUsage", size)
	if err != nil {
		return 0, fmt.Errorf("failed to increment bin usage: %w", err)
	}

	binUsage, ok := res["BinUsage"]
	if !ok {
		return 0, errors.New("BinUsage is not present in the response")
	}

	binUsageAttr, ok := binUsage.(*types.AttributeValueMemberN)
	if !ok {
		return 0, fmt.Errorf("unexpected type for BinUsage: %T", binUsage)
	}

	binUsageValue, err := strconv.ParseUint(binUsageAttr.Value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse BinUsage: %w", err)
	}

	return binUsageValue, nil
}

func (s *OffchainStore) UpdateGlobalBin(ctx context.Context, binIndex uint64, size uint64) (uint64, error) {
	key := map[string]types.AttributeValue{
		"BinIndex": &types.AttributeValueMemberN{Value: strconv.FormatUint(binIndex, 10)},
	}

	res, err := s.dynamoClient.IncrementBy(ctx, s.globalBinTableName, key, "BinUsage", size)
	if err != nil {
		return 0, err
	}

	binUsage, ok := res["BinUsage"]
	if !ok {
		return 0, nil
	}

	binUsageAttr, ok := binUsage.(*types.AttributeValueMemberN)
	if !ok {
		return 0, nil
	}

	binUsageValue, err := strconv.ParseUint(binUsageAttr.Value, 10, 32)
	if err != nil {
		return 0, err
	}

	return binUsageValue, nil
}

func (s *OffchainStore) AddOnDemandPayment(ctx context.Context, paymentMetadata core.PaymentMetadata, symbolsCharged uint32) error {
	result, err := s.dynamoClient.GetItem(ctx, s.onDemandTableName,
		commondynamodb.Item{
			"AccountID":          &types.AttributeValueMemberS{Value: paymentMetadata.AccountID},
			"CumulativePayments": &types.AttributeValueMemberN{Value: paymentMetadata.CumulativePayment.String()},
		},
	)
	if err != nil {
		fmt.Println("new payment record: %w", err)
	}
	if result != nil {
		return fmt.Errorf("exact payment already exists")
	}
	err = s.dynamoClient.PutItem(ctx, s.onDemandTableName,
		commondynamodb.Item{
			"AccountID":          &types.AttributeValueMemberS{Value: paymentMetadata.AccountID},
			"CumulativePayments": &types.AttributeValueMemberN{Value: paymentMetadata.CumulativePayment.String()},
			"DataLength":         &types.AttributeValueMemberN{Value: strconv.FormatUint(uint64(symbolsCharged), 10)},
		},
	)

	if err != nil {
		return fmt.Errorf("failed to add payment: %w", err)
	}
	return nil
}

// RemoveOnDemandPayment removes a specific payment from the list for a specific account
func (s *OffchainStore) RemoveOnDemandPayment(ctx context.Context, accountID string, payment *big.Int) error {
	err := s.dynamoClient.DeleteItem(ctx, s.onDemandTableName,
		commondynamodb.Key{
			"AccountID":          &types.AttributeValueMemberS{Value: accountID},
			"CumulativePayments": &types.AttributeValueMemberN{Value: payment.String()},
		},
	)

	if err != nil {
		return fmt.Errorf("failed to remove payment: %w", err)
	}

	return nil
}

// GetRelevantOnDemandRecords gets previous cumulative payment, next cumulative payment, blob size of next payment
// The queries are done sequentially instead of one-go for efficient querying and would not cause race condition errors for honest requests
func (s *OffchainStore) GetRelevantOnDemandRecords(ctx context.Context, accountID string, cumulativePayment *big.Int) (uint64, uint64, uint32, error) {
	// Fetch the largest entry smaller than the given cumulativePayment
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String(s.onDemandTableName),
		KeyConditionExpression: aws.String("AccountID = :account AND CumulativePayments < :cumulativePayment"),
		ExpressionAttributeValues: commondynamodb.ExpressionValues{
			":account":           &types.AttributeValueMemberS{Value: accountID},
			":cumulativePayment": &types.AttributeValueMemberN{Value: cumulativePayment.String()},
		},
		ScanIndexForward: aws.Bool(false),
		Limit:            aws.Int32(1),
	}
	smallerResult, err := s.dynamoClient.QueryWithInput(ctx, queryInput)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to query smaller payments for account: %w", err)
	}
	var prevPayment uint64
	if len(smallerResult) > 0 {
		prevPayment, err = strconv.ParseUint(smallerResult[0]["CumulativePayments"].(*types.AttributeValueMemberN).Value, 10, 64)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("failed to parse previous payment: %w", err)
		}
	}

	// Fetch the smallest entry larger than the given cumulativePayment
	queryInput = &dynamodb.QueryInput{
		TableName:              aws.String(s.onDemandTableName),
		KeyConditionExpression: aws.String("AccountID = :account AND CumulativePayments > :cumulativePayment"),
		ExpressionAttributeValues: commondynamodb.ExpressionValues{
			":account":           &types.AttributeValueMemberS{Value: accountID},
			":cumulativePayment": &types.AttributeValueMemberN{Value: cumulativePayment.String()},
		},
		ScanIndexForward: aws.Bool(true),
		Limit:            aws.Int32(1),
	}
	largerResult, err := s.dynamoClient.QueryWithInput(ctx, queryInput)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to query the next payment for account: %w", err)
	}
	var nextPayment uint64
	var nextDataLength uint32
	if len(largerResult) > 0 {
		nextPayment, err = strconv.ParseUint(largerResult[0]["CumulativePayments"].(*types.AttributeValueMemberN).Value, 10, 64)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("failed to parse next payment: %w", err)
		}
		dataLength, err := strconv.ParseUint(largerResult[0]["DataLength"].(*types.AttributeValueMemberN).Value, 10, 32)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("failed to parse blob size: %w", err)
		}
		nextDataLength = uint32(dataLength)
	}

	return prevPayment, nextPayment, nextDataLength, nil
}

func (s *OffchainStore) GetBinRecords(ctx context.Context, accountID string, binIndex uint32) ([3]*pb.BinRecord, error) {
	// Fetch the 3 bins start from the current bin
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String(s.reservationTableName),
		KeyConditionExpression: aws.String("AccountID = :account AND BinIndex > :binIndex"),
		ExpressionAttributeValues: commondynamodb.ExpressionValues{
			":account":  &types.AttributeValueMemberS{Value: accountID},
			":binIndex": &types.AttributeValueMemberN{Value: strconv.FormatUint(uint64(binIndex), 10)},
		},
		ScanIndexForward: aws.Bool(true),
		Limit:            aws.Int32(MinNumBins),
	}
	bins, err := s.dynamoClient.QueryWithInput(ctx, queryInput)
	if err != nil {
		return [3]*pb.BinRecord{}, fmt.Errorf("failed to query payments for account: %w", err)
	}

	records := [3]*pb.BinRecord{}
	for i := 0; i < len(bins) && i < 3; i++ {
		binRecord, err := parseBinRecord(bins[i])
		if err != nil {
			return [3]*pb.BinRecord{}, fmt.Errorf("failed to parse bin %d record: %w", i, err)
		}
		records[i] = binRecord
	}

	return records, nil
}

func (s *OffchainStore) GetLargestCumulativePayment(ctx context.Context, accountID string) (*big.Int, error) {
	// Fetch the largest cumulative payment
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String(s.onDemandTableName),
		KeyConditionExpression: aws.String("AccountID = :account"),
		ExpressionAttributeValues: commondynamodb.ExpressionValues{
			":account": &types.AttributeValueMemberS{Value: accountID},
		},
		ScanIndexForward: aws.Bool(false),
		Limit:            aws.Int32(1),
	}
	payments, err := s.dynamoClient.QueryWithInput(ctx, queryInput)
	if err != nil {
		return nil, fmt.Errorf("failed to query payments for account: %w", err)
	}

	if len(payments) == 0 {
		return nil, nil
	}

	payment, err := strconv.ParseUint(payments[0]["CumulativePayments"].(*types.AttributeValueMemberN).Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse payment: %w", err)
	}

	return new(big.Int).SetUint64(payment), nil
}

// DeleteOldBins removes all reservation bin entries with indices less than the provided binIndex
func (s *OffchainStore) DeleteOldBins(ctx context.Context, binIndex uint32) error {
	// get all keys that need to be deleted
	queryInput := &dynamodb.QueryInput{
		TableName:        aws.String(s.reservationTableName),
		FilterExpression: aws.String("BinIndex < :binIndex"),
		ExpressionAttributeValues: commondynamodb.ExpressionValues{
			":binIndex": &types.AttributeValueMemberN{Value: strconv.FormatUint(uint64(binIndex), 10)},
		},
	}

	items, err := s.dynamoClient.QueryWithInput(ctx, queryInput)
	if err != nil {
		return fmt.Errorf("failed to query old bins: %w", err)
	}

	keys := make([]commondynamodb.Key, len(items))
	for i, item := range items {
		keys[i] = commondynamodb.Key{
			"AccountID": item["AccountID"],
			"BinIndex":  item["BinIndex"],
		}
	}

	// Delete the items in batches
	if len(keys) > 0 {
		failedKeys, err := s.dynamoClient.DeleteItems(ctx, s.reservationTableName, keys)
		if err != nil {
			return fmt.Errorf("failed to delete old bins: %w", err)
		}
		if len(failedKeys) > 0 {
			return fmt.Errorf("failed to delete %d bins", len(failedKeys))
		}
	}

	return nil
}

func parseBinRecord(bin map[string]types.AttributeValue) (*pb.BinRecord, error) {
	binIndex, ok := bin["BinIndex"]
	if !ok {
		return nil, errors.New("BinIndex is not present in the response")
	}

	binIndexAttr, ok := binIndex.(*types.AttributeValueMemberN)
	if !ok {
		return nil, fmt.Errorf("unexpected type for BinIndex: %T", binIndex)
	}

	binIndexValue, err := strconv.ParseUint(binIndexAttr.Value, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse BinIndex: %w", err)
	}

	binUsage, ok := bin["BinUsage"]
	if !ok {
		return nil, errors.New("BinUsage is not present in the response")
	}

	binUsageAttr, ok := binUsage.(*types.AttributeValueMemberN)
	if !ok {
		return nil, fmt.Errorf("unexpected type for BinUsage: %T", binUsage)
	}

	binUsageValue, err := strconv.ParseUint(binUsageAttr.Value, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse BinUsage: %w", err)
	}

	return &pb.BinRecord{
		Index: uint32(binIndexValue),
		Usage: uint64(binUsageValue),
	}, nil
}

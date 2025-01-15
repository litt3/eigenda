package codec_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/Layr-Labs/eigenda/common/testutils/random"
	"github.com/Layr-Labs/eigenda/encoding/rs"
	"github.com/Layr-Labs/eigenda/encoding/utils/codec"
	"github.com/stretchr/testify/require"
)

func TestSimplePaddingCodec(t *testing.T) {
	gettysburgAddressBytes := []byte("Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.")

	paddedData := codec.ConvertByPaddingEmptyByte(gettysburgAddressBytes)

	restored := codec.RemoveEmptyByteFromPaddedBytes(paddedData)

	require.Equal(t, gettysburgAddressBytes, restored[:len(gettysburgAddressBytes)])
}

func TestSimplePadding_IsValid(t *testing.T) {
	gettysburgAddressBytes := []byte("Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.")

	paddedData := codec.ConvertByPaddingEmptyByte(gettysburgAddressBytes)

	_, err := rs.ToFrArray(paddedData)
	require.Nil(t, err)
}

func TestSimplePaddingCodec_Fuzz(t *testing.T) {
	numFuzz := 100

	dataSizeList := make([]int, 0)
	for i := 32; i < 3000; i = i + 10 {
		dataSizeList = append(dataSizeList, i)
	}

	for i := 0; i < numFuzz; i++ {
		for j := 0; j < len(dataSizeList); j++ {
			data := make([]byte, dataSizeList[j])
			_, err := rand.Read(data)
			require.Nil(t, err)
			paddedData := codec.ConvertByPaddingEmptyByte(data)
			_, err = rs.ToFrArray(paddedData)
			require.Nil(t, err)
			restored := codec.RemoveEmptyByteFromPaddedBytes(paddedData)
			require.Equal(t, data, restored)
		}
	}
}

// TestCodec tests the encoding and decoding of random byte streams
func TestPayloadEncoding(t *testing.T) {
	testRandom := random.NewTestRandom(t)

	// Number of test iterations
	const iterations = 100

	for i := 0; i < iterations; i++ {
		originalData := testRandom.Bytes(testRandom.Intn(1024) + 1)

		// Encode the original data
		encodedData := codec.EncodePayload(originalData)

		// Decode the encoded data
		decodedData, err := codec.DecodePayload(encodedData)
		if err != nil {
			t.Fatalf("Iteration %d: failed to decode blob: %v", i, err)
		}

		// Compare the original data with the decoded data
		if !bytes.Equal(originalData, decodedData) {
			t.Fatalf(
				"Iteration %d: original and decoded data do not match\nOriginal: %v\nDecoded: %v",
				i,
				originalData,
				decodedData)
		}
	}
}

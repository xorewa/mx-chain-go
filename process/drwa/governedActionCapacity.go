package drwa

import "encoding/binary"

// governedActionCapacityFits verifies that the configured total can actually
// be represented by the existing native Batch aggregate within its byte bound.
// Every member has a fixed-size action ID and one category byte. This computes
// the native framed size arithmetically, without allocating a full aggregate or
// selecting any profile's numeric capacity.
func governedActionCapacityFits(total, hashBytes, maxBytes uint64) bool {
	// The native codec takes int-sized inputs. Keeping the inputs within this
	// range makes the small framing additions below safe in uint64.
	if total == 0 || hashBytes == 0 || hashBytes > maxBytes || maxBytes > uint64(^uint(0)>>1) {
		return false
	}
	width := func(payload uint64) uint64 {
		var encoded [binary.MaxVarintLen64]byte
		return 1 + uint64(binary.PutUvarint(encoded[:], payload)) + payload
	}
	member := width(width(hashBytes) + width(1))
	fixed := 2*width(8) + width(hashBytes)
	if fixed >= maxBytes || total > (maxBytes-fixed)/member {
		return false
	}
	// The division above also proves that this multiplication cannot overflow.
	return width(total*member) <= maxBytes-fixed
}

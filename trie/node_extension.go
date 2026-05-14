package trie

// The trie fault-injection helpers (shouldTestNode, snapshotGetTestPoint
// and the faultyChance constant) that previously lived in this file
// were moved to node_extension_test.go after audit ISSUE-034. They are
// test-only by design and had no production callers. This file is kept
// as a placeholder so that historical references to its path remain
// intact; it can be removed entirely once the operator confirms no
// downstream tooling expects the path to exist.

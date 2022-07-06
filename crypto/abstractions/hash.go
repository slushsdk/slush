package crypto

type iHash struct {
	Size int64
}

func (hash iHash) New() iHash {
	return iHash{0}
}

func (hash iHash) Write(b []byte) iHash {
	return iHash{0}
}

func (hash iHash) Sum() {
	//return iHash{0}
}

func (hash iHash) Sum256(b []byte) {
	//return iHash{0}
}

func (hahs iHash) Reset() iHash {
	return iHash{0}
}

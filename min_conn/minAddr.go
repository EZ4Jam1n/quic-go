package min_conn

type MinPushAddr struct {
	Addr string
}

func (m *MinPushAddr) Network() string {
	return "MIN"
}

func (m *MinPushAddr) String() string {
	return m.Addr
}

func NewMinPushAddr(a string) *MinPushAddr {
	return &MinPushAddr{Addr: a}
}

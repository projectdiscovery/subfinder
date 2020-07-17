package github

import "time"

type token struct {
	Hash         string
	ExceededTime time.Time
  RetryAfter int64
}

type Tokens struct {
	current int
	pool    []token
}

func NewTokenManager(keys []string) *Tokens {
	pool := []token{}
	for _, key := range keys {
		t := token{Hash: key, ExceededTime: time.Time{}, RetryAfter: 0}
		pool = append(pool, t)
	}

	return &Tokens{
		current: 0,
		pool:    pool,
	}
}

func (r *Tokens) setCurrentTokenExceeded(retryAfter int64) {
  if r.current >= len(r.pool) {
		r.current = r.current % len(r.pool)
	}
  if r.pool[r.current].RetryAfter == 0 {
    r.pool[r.current].ExceededTime = time.Now()
    r.pool[r.current].RetryAfter = retryAfter
  }
}

func (r *Tokens) Get() token {
  resetExceededTokens(r)

	if r.current >= len(r.pool) {
		r.current = r.current % len(r.pool)
	}

	result := r.pool[r.current]
	r.current++

	return result
}

func resetExceededTokens(r *Tokens) {
  for i, token := range r.pool {
    if token.RetryAfter > 0 {
      if int64(time.Since(token.ExceededTime) / time.Second) > token.RetryAfter {
        r.pool[i].ExceededTime = time.Time{}
        r.pool[i].RetryAfter = 0
      }
    }
  }
}

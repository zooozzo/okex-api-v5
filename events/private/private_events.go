package private

import (
	"github.com/cocoyes/okex/events"
	"github.com/cocoyes/okex/models/account"
	"github.com/cocoyes/okex/models/trade"
)

type (
	Account struct {
		Arg      *events.Argument   `json:"arg"`
		Balances []*account.Balance `json:"data"`
	}
	Position struct {
		Arg       *events.Argument    `json:"arg"`
		Positions []*account.Position `json:"data"`
	}
	BalanceAndPosition struct {
		Arg                 *events.Argument              `json:"arg"`
		BalanceAndPositions []*account.BalanceAndPosition `json:"data"`
	}
	Order struct {
		Arg    *events.Argument `json:"arg"`
		Orders []*trade.Order   `json:"data"`
	}
	AlgoOrder struct {
		Arg    *events.Argument   `json:"arg"`
		Orders []*trade.AlgoOrder `json:"data"`
	}
)

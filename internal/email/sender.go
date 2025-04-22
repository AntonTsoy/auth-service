package email

import (
	"fmt"
	"time"
)

func SendEmailWarning(newIPAddress string) {
	time.Sleep(5 * time.Second)
	fmt.Printf("Email notification! Warning: IP address changed to %s.\n", newIPAddress)
}

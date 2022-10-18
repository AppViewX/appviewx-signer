package monitor

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (

	// Shows the total Number of CSR requests received as of now
	CSRCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name:        "kubernetes_csr",
			Help:        "AppViewX - Kubernetes CSR Count",
			ConstLabels: prometheus.Labels{"status": "received"},
		},
	)

	// Shows the total number of Success Certificate Response from AppViewX
	AppViewXCertificateSuccessCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name:        "appviewx_certificate_request",
			Help:        "AppViewX - Certificate Request Count",
			ConstLabels: prometheus.Labels{"success": "true"},
		},
	)

	//Shows the total number of Failure Certificate Response from AppViewX
	AppViewXCertificateFailureCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name:        "appviewx_certificate_request",
			Help:        "AppViewX - Certificate Request Count",
			ConstLabels: prometheus.Labels{"success": "false"},
		},
	)

	//Shows the total number of JWT Token Read Count from the file system
	JWTTokenReadCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name:        "jwt_token_read",
			Help:        "AppViewX - JWT Token Read Count",
			ConstLabels: prometheus.Labels{"status": "read"},
		},
	)

	//Shows the total number of AppViewX Login Success
	AppViewXLoginSuccessCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name:        "appviewx_login",
			Help:        "AppViewX - Login Count",
			ConstLabels: prometheus.Labels{"success": "true"},
		},
	)

	//Shows the total number of AppViewX Login Failure
	AppViewXLoginFailureCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name:        "appviewx_login",
			Help:        "AppViewX - Login Count",
			ConstLabels: prometheus.Labels{"success": "false"},
		},
	)
)

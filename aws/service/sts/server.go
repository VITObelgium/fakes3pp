package sts


type STSServer struct{
	jwtPrivateRSAKey string //TODO fix

	JwtPublicRSAKey string //TODO fix type

	fqdns []string

	port  int

	tlsCert string //TODO fix type

	tlsKey string //TODO fix type

	secure bool //TODO? required could be deduced from the above 2 

	oidcConfig string //TODO fix type

	rolePolicyPath string //TODO probably change to a pm

	maxDurationSeconds int32
}


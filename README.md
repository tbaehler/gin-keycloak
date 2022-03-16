# Gin-Keycloak


Gin-Keycloak is specially made for [Gin Framework](https://github.com/gin-gonic/gin)
users who also want to use Keycoak. 
This Project was inspired by zalando's gin-oauth 

## Project Context and Features

When it comes to choosing a Go framework, there's a lot of confusion
about what to use. The scene is very fragmented, and detailed
comparisons of different frameworks are still somewhat rare. Meantime,
how to handle dependencies and structure projects are big topics in
the Go community. We've liked using Gin for its speed,
accessibility, and usefulness in developing microservice
architectures. In creating Gin-OAuth2, we wanted to take fuller
advantage of Gin's capabilities and help other devs do likewise.

Gin-Keycloak is expressive, flexible, and very easy to use. It allows you to:
- do OAuth2 authorization based on the JWT Token
- create router groups to place Keycloak authorization on top, using HTTP verbs and passing them
- more easily decouple services by promoting a "say what to do, not how to do it" approach
- configure your REST API directly in the code (see the "Usage" example below)
- write your own authorization functions

## Requirements

- [Gin](https://github.com/gin-gonic/gin)
- An Keycloak Token provider

Gin-Keycloak uses the following [Go](https://golang.org/) packages as
dependencies:

* [Gin](https://github.com/gin-gonic/gin)
* [glog](https://github.com/golang/glog)
* [gin-glog](https://github.com/szuecs/gin-glog)

## Installation

Assuming you've installed Go and Gin, run this:

    go get github.com/tbaehler/gin-keycloak

## Usage

### Authentication-Based Access

With this function you just check if user is authenticated. Therefore there is no need for AccessTuple unlike next two access types.

Gin middlewares you use:

	router := gin.New()
	router.Use(ginglog.Logger(3 * time.Second))
	router.Use(ginkeycloak.RequestLogger([]string{"uid"}, "data"))
	router.Use(gin.Recovery())

A Keycloakconfig. You can either use URL and Realm or define a fullpath that point to protocol/openid-connect/certs 

    var sbbEndpoint = ginkeycloak.KeycloakConfig{
	    Url:  "https://keycloack.domain.ch/",
	    Realm: "Your Realm",
        FullCertsPath: nil
    }

Lastly, define which type of access you grant to the defined
team. We'll use a router group again:


	privateGroup := router.Group("/api/privateGroup")
	privateGroup.Use(ginkeycloak.Auth(ginkeycloak.AuthCheck(), keycloakconfig))
	privateGroup.GET("/", func(c *gin.Context) {
		....
	})

Once again, you can use curl to test:

        curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateGroup/
        {"message":"Hello from private to sszuecs member of teapot"}


### Uid-Based Access

Restrict all access but for a few users

    config := ginkeycloak.BuilderConfig{
              		service:              <yourServicename>,
              		url:                  "<your token url>",
              		realm:                "<your realm to get the public keys>",
              }
    
	router := gin.New()
	privateUser := router.Group("/api/privateUser")
	
	privateUser.Use(ginkeycloak.NewAccessBuilder(config).
        RestrictButForUid("domain\user1").
        RestrictButForUid("domain\user2").
        Build())
        
	privateUser.GET("/", func(c *gin.Context) {
		....
	})

#### Testing

To test, you can use curl:

        curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateUser/
        {"message":"Hello from private for users to Sandor Szücs"}

### Role-Based Access

Restrict all access but for the given roles

        
    config := ginkeycloak.BuilderConfig{
                  		service:              <yourServicename>,
                  		url:                  "<your token url>",
                  		realm:                "<your realm to get the public keys>",
                  }
        
    router := gin.New()
    privateUser := router.Group("/api/privateUser")
    
    privateUser.Use(ginkeycloak.NewAccessBuilder(config).
        RestrictButForRole("role1").
        RestrictButForRole("role2").
        Build())
        
    privateUser.GET("/", func(c *gin.Context) {
    	....
    })

Once again, you can use curl to test:

    curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateGroup/
        {"message":"Hello from private to sszuecs member of teapot"}

### Realm-Based Access

Realm Based Access is also possible and straightforward:

        
    config := ginkeycloak.BuilderConfig{
                      		service:              <yourServicename>,
                      		url:                  "<your token url>",
                      		realm:                "<your realm to get the public keys>",
                      }
            
    router := gin.New()
    privateUser := router.Group("/api/privateUser")
    
    privateUser.Use(ginkeycloak.NewAccessBuilder(config).
        RestrictButForRealm("realmRole").
        Build())
        
    privateUser.GET("/", func(c *gin.Context) {
    	....
    })

## FAQ

#### Which Token Signature Algorithms are currently supported?
Currently, are only "EC" (which uses keycloak by default) and "RS" supported

#### How to get the keycloak claims e.g. sub, mail, name?

        ginToken,_ := context.Get("token")
        token := ginToken.(ginkeycloak.KeyCloakToken)


## Contributors

Thanks to:

- Zalando Team for their initial work 

## License

See MIT-License [LICENSE](LICENSE) file.

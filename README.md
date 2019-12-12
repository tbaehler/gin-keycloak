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

A Keycloakconfig

    var sbbEndpoint = ginkeycloak.KeycloakConfig{
	    Url:  "https://keycloack.domain.ch/",
	    Realm: "Your Realm",
    }

Lastly, define which type of access you grant to the defined
team. We'll use a router group again:


	privateGroup := router.Group("/api/privateGroup")
	privateGroup.Use(ginkeycloak.Auth(ginkeycloak.GroupCheck(GRANTED_ROLE), keycloakconfig))
	privateGroup.GET("/", func(c *gin.Context) {
		....
	})

Once again, you can use curl to test:

        curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateGroup/
        {"message":"Hello from private to sszuecs member of teapot"}

### Uid-Based Access

First, define your access triples to identify who has access to a
given resource. This snippet shows how to grant resource access to two
hypothetical employees:

    //from ginkeycloak package
    // AccessTuple is the type defined for use in AccessTuples.
      
            type AccessTuple struct {
           	    Service string
           	    Role    string
           	    Uid     string
            }
        
    var GRANTED_USERS  = []ginkeycloak.AccessTuple{{Uid: "domain\user1"}}


Next, define which Gin middlewares you use. The third line in this
snippet is a basic audit log:

	router := gin.New()
	router.Use(ginglog.Logger(3 * time.Second))
	router.Use(ginkeycloak.RequestLogger([]string{"uid"}, "data"))
	router.Use(gin.Recovery())

Finally, define which type of access you grant to the defined
users. We'll use a router group, so that we can add a bunch of router
paths and HTTP verbs:

	privateUser := router.Group("/api/privateUser")
	privateUser.Use(ginkeycloak.Auth(ginkeycloak.UidCheck(USERS), keycloakConfig))
	privateUser.GET("/", func(c *gin.Context) {
		....
	})

#### Testing

To test, you can use curl:

        curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateUser/
        {"message":"Hello from private for users to Sandor Szücs"}

### Role-Based Access

As with Uid-based access, define your access triples to identify who
has access to a given resource. With this snippet, you can grant resource
access to an entire team instead of individuals:

        
    var GRANTED_ROLE  = []ginkeycloak.AccessTuple{
	    {Service: "keycloak-service", Role: "keycloak-role"},
    }


Now define which Gin middlewares you use:

	router := gin.New()
	router.Use(ginglog.Logger(3 * time.Second))
	router.Use(ginkeycloak.RequestLogger([]string{"uid"}, "data"))
	router.Use(gin.Recovery())

A Keycloakconfig

    var sbbEndpoint = ginkeycloak.KeycloakConfig{
	    Url:  "https://keycloack.domain.ch/",
	    Realm: "Your Realm",
    }

Lastly, define which type of access you grant to the defined
team. We'll use a router group again:


	privateGroup := router.Group("/api/privateGroup")
	privateGroup.Use(ginkeycloak.Auth(ginkeycloak.GroupCheck(GRANTED_ROLE), keycloakconfig))
	privateGroup.GET("/", func(c *gin.Context) {
		uid, okUid := c.Get("uid")
		....
	})

Once again, you can use curl to test:

        curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateGroup/
        {"message":"Hello from private to sszuecs member of teapot"}


## Contributors

Thanks to:

- Zalando Team for their initial work 

## License

See MIT-License [LICENSE](LICENSE) file.

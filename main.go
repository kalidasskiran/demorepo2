package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type MenuItem struct {
	ID          primitive.ObjectID `json:"id" bson:"_id"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Cost        string             `json:"cost" bson:"cost"`
	Timeofentry time.Time          `json:"timeofentry" bson:"timeofentry"`
}

//jwt
type AuthHandler struct{}
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}
type JWTOutput struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

type User struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

func (handler *AuthHandler) SignInHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if user.Username != "admin" || user.Password !=
		"password" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}
	expirationTime := time.Now().Add(10 * time.Minute)
	claims := &Claims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		claims)
	tokenString, err := token.SignedString([]byte(
		os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			gin.H{"error": err.Error()})
		return
	}
	jwtOutput := JWTOutput{
		Token:   tokenString,
		Expires: expirationTime,
	}
	c.JSON(http.StatusOK, jwtOutput)
}

var authHandler AuthHandler

//jwt end
var menuitems []MenuItem
var ctx context.Context
var err error
var client *mongo.Client

func init() {

	ctx = context.Background()
	client, err = mongo.Connect(ctx,
		options.Client().ApplyURI(os.Getenv("MONGO_URI")))
	if err = client.Ping(context.TODO(),
		readpref.Primary()); err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to MongoDB")
	authHandler = AuthHandler{}
}

func NewMenuItemHandler(c *gin.Context) {
	var menuitem MenuItem
	collection := client.Database(os.Getenv(
		"MONGO_DATABASE")).Collection("Menu")
	if err := c.ShouldBindJSON(&menuitem); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error()})
		return
	}

	menuitem.ID = primitive.NewObjectID()
	menuitem.Timeofentry = time.Now()

	_, err = collection.InsertOne(ctx, menuitem)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError,
			gin.H{"error": "Error while inserting a new menu item"})
		return
	}
	c.JSON(http.StatusOK, menuitem)
}

func ListMenuItemsHandler(c *gin.Context) {
	collection := client.Database(os.Getenv(
		"MONGO_DATABASE")).Collection("Menu")
	cur, err := collection.Find(ctx, bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			gin.H{"error": err.Error()})
		return
	}
	defer cur.Close(ctx)
	menuitems := make([]MenuItem, 0)
	for cur.Next(ctx) {
		var menuitem MenuItem
		cur.Decode(&menuitem)
		menuitems = append(menuitems, menuitem)
	}
	c.JSON(http.StatusOK, menuitems)
}

func UpdateMenuItemsHandler(c *gin.Context) {
	id := c.Param("id")
	var menuitem MenuItem
	if err := c.ShouldBindJSON(&menuitem); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error()})
		return
	}
	objectId, _ := primitive.ObjectIDFromHex(id)
	collection := client.Database(os.Getenv(
		"MONGO_DATABASE")).Collection("Menu")
	_, err = collection.UpdateOne(ctx, bson.M{
		"_id": objectId,
	}, bson.D{{"$set", bson.D{
		{"name", menuitem.Name},
		{"description", menuitem.Description},
		{"cost", menuitem.Cost},
	}}})
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError,
			gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Menu item has been updated"})
}
func (handler *AuthHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenValue := c.GetHeader("Authorization")
		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(tokenValue, claims,
			func(token *jwt.Token) (interface{}, error) {
				return []byte(os.Getenv("JWT_SECRET")), nil
			})
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		if tkn == nil || !tkn.Valid {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		c.Next()
	}
}
func main() {
	router := gin.Default()
	router.GET("/menu", ListMenuItemsHandler)
	router.POST("/signin", authHandler.SignInHandler)

	router.POST("/menu", NewMenuItemHandler)

	router.PUT("/menu/:id", UpdateMenuItemsHandler)

	router.Run()
}

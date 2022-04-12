package handlers

import (
	"context"
	"menusplit/models"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mlabouardy/recipes-api/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/net/context"

	"go.mongodb.org/mongo-driver/mongo"
)

type MenuItemsHandler struct {
	collection *mongo.Collection
	ctx        context.Context
}

func NewMenuItemssHandler(ctx context.Context, collection *mongo.
	Collection) *MenuItemsHandler {
	return &MenuItemsHandler{
		collection: collection,
		ctx:        ctx,
	}
}

func (handler *MenuItemsHandler) ListMenuItemsHandler(c *gin.
	Context) {
	cur, err := handler.collection.Find(handler.ctx, bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			gin.H{"error": err.Error()})
		return
	}
	defer cur.Close(handler.ctx)
	menuitems := make([]models.MenuItem, 0)
	for cur.Next(handler.ctx) {
		var menuitem models.MenuItem
		cur.Decode(&menuitem)
		menuitems = append(menuitems, menuitem)
	}
	c.JSON(http.StatusOK, menuitems)
}

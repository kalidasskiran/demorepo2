package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type MenuItem struct {
	ID          primitive.ObjectID `json:"id" bson:"_id"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Cost        string             `json:"cost" bson:"cost"`
	Timeofentry time.Time          `json:"timeofentry" bson:"timeofentry"`
}

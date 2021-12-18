package api

import "time"

type KubeCSR struct {
	ClusterName string    `json:"clusterName" binding:"required"`
	Timestamp   time.Time `json:"timestamp"`
	RequesterIP string    `json:"requesterIP"`
	User        string    `json:"user,required" binding:"required"`
}

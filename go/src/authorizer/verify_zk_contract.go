package main

import (
	"encoding/json"
	"github.com/orbs-network/contract-library-experiment/collections"
	"github.com/orbs-network/orbs-contract-sdk/go/sdk/v1"
)

var PUBLIC = sdk.Export(VerifyZKProof)
var SYSTEM = sdk.Export(_init)

func _init() {

}

func VerifyZKProof(artist string, album string) {
	albums := collections.NewStringList(artist)
	albums.Add(album)
}

func getAlbums(artist string) string {
	albums := collections.NewStringList(artist)

	var results []string
	albums.Iterate(func(id uint64, item interface{}) bool {
		results = append(results, item.(string))
		return true
	})

	data, err := json.Marshal(results)
	if err != nil {
		panic(err)
	}

	return string(data)
}

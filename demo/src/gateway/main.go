package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
)

// Demo fixture: deliberately vulnerable. Never built or run.

func noteHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		query := fmt.Sprintf("SELECT title, body FROM notes WHERE id = %s", id)
		rows, err := db.Query(query)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()
		c.JSON(http.StatusOK, gin.H{"rows": rows})
	}
}

func thumbHandler(c *gin.Context) {
	name := c.Query("name")
	out, err := exec.Command("convert", "/srv/gateway/"+name, "/tmp/out.png").Output()
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	c.String(http.StatusOK, string(out))
}

func fileHandler(c *gin.Context) {
	data, err := os.ReadFile("/srv/gateway/storage/" + c.Query("file"))
	if err != nil {
		c.String(http.StatusNotFound, "missing")
		return
	}
	c.String(http.StatusOK, string(data))
}

func main() {
	db, _ := sql.Open("sqlite3", "/srv/gateway/notes.sqlite3")
	r := gin.Default()
	r.GET("/notes/:id", noteHandler(db))
	r.GET("/thumb", thumbHandler)
	r.GET("/file", fileHandler)
	r.Run("0.0.0.0:8084")
}

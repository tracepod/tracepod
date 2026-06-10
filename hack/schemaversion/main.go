// Command schemaversion prints the integer profile schema version the sensor
// currently emits (manifest.SchemaVersion). Used by hack/record-profile-fixtures.sh
// so the fixtures directory always matches the wire version.
package main

import (
	"fmt"

	"github.com/tracepod/tracepod/manifest"
)

func main() {
	fmt.Println(manifest.SchemaVersion)
}

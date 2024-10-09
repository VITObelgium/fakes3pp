// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//Original source: https://github.com/minio/minio/blob/master/cmd/api-headers.go

package cmd

import (
	"bytes"
	"context"
	"encoding/xml"
	"log/slog"
)

// Encodes the response headers into XML format.
func encodeResponse(ctx context.Context, response interface{}) []byte {
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	if err := xml.NewEncoder(&buf).Encode(response); err != nil {
		slog.Error("Could not encode xml response", " error", err, xRequestIDStr, getRequestID(ctx))
		return nil
	}
	return buf.Bytes()
}

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

//Original source: https://github.com/minio/minio/blob/master/cmd/api-response.go

package cmd

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-http-utils/headers"
)

func writeResponse(ctx context.Context, w http.ResponseWriter, statusCode int, response []byte, mType mimeType) {
	if statusCode == 0 {
		statusCode = 200
	}
	// Similar check to http.checkWriteHeaderCode
	if statusCode < 100 || statusCode > 999 {
		slog.ErrorContext(ctx, "Internal server error", "error", "invalid WriteHeader code", "statusCode", statusCode)
		statusCode = http.StatusInternalServerError
	}
	if mType != mimeNone {
		w.Header().Set(headers.ContentType, string(mType))
	}
	w.Header().Set(headers.ContentLength, strconv.Itoa(len(response)))
	w.WriteHeader(statusCode)
	if response != nil {
		WriteButLogOnError(ctx, w, response)
	}
}

// writeSuccessResponseXML writes success headers and response if any,
// with content-type set to `application/xml`.
func writeSuccessResponseXML(ctx context.Context, w http.ResponseWriter, response []byte) {
	writeResponse(ctx, w, http.StatusOK, response, mimeXML)
}

// mimeType represents various MIME type used API responses.
type mimeType string

const (
	// Means no response type.
	mimeNone mimeType = ""
	// Means response type is XML.
	mimeXML mimeType = "application/xml"
)
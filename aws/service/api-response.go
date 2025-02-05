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

package service

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/VITObelgium/fakes3pp/utils"
	"github.com/go-http-utils/headers"
)

func WriteResponse(ctx context.Context, w http.ResponseWriter, statusCode int, response []byte, mType MimeType) {
	if statusCode == 0 {
		statusCode = 200
	}
	// Similar check to http.checkWriteHeaderCode
	if statusCode < 100 || statusCode > 999 {
		slog.ErrorContext(ctx, "Internal server error", "error", "invalid WriteHeader code", "statusCode", statusCode)
		statusCode = http.StatusInternalServerError
	}
	if mType != MimeNone {
		w.Header().Set(headers.ContentType, string(mType))
	}
	w.Header().Set(headers.ContentLength, strconv.Itoa(len(response)))
	w.WriteHeader(statusCode)
	if response != nil {
		utils.WriteButLogOnError(ctx, w, response)
	}
}

// WriteSuccessResponseXML writes success headers and response if any,
// with content-type set to `application/xml`.
func WriteSuccessResponseXML(ctx context.Context, w http.ResponseWriter, response []byte) {
	WriteResponse(ctx, w, http.StatusOK, response, MimeXML)
}

// MimeType represents various MIME type used API responses.
type MimeType string

const (
	// Means no response type.
	MimeNone MimeType = ""
	// Means response type is XML.
	MimeXML MimeType = "application/xml"
)


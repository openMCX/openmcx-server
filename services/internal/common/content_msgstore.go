// Upload by reference of the MCData content server: a file of the uploader's MCData message store account,
// fetched from the message store and stored by the media storage function.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), OMA RESTful Network API for Network Message Storage (NMS),
// RFC 2017.
package common

import (
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// ------------------------------------------------------------------------------
// TS 24.282 clause 10.2.2.2 (second list, step 2b): upload by reference. The upload names, in a
// message/external-body part with access-type URL (RFC 2017), the payload of an object in the uploader's own
// MCData message store account (//{serverRoot}/nms/v1/{storeName}/{boxId}/objects/{objectId}/payload,
// TS 24.282 clause 10.2.2.1 NOTE 3). The media storage function fetches it with the uploader's access token
// (TS 24.282 clause 6.7.2.1) and stores it as if it had been uploaded.
func (svc *service) fetchNetworkStoredFile(request *http.Request, claims TokenClaims, part *multipart.Part, directory string, limit int64) (*StoredFile, int, error) {
	_, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(params["access-type"], "URL") || params["url"] == "" {
		return nil, http.StatusBadRequest, errors.New("message/external-body needs access-type URL and a URL")
	}
	source, err := url.Parse(params["url"])
	if err != nil || source.Scheme != "https" {
		return nil, http.StatusBadRequest, errors.New("the network-stored file URL must be an https URL")
	}
	// Only the uploader's own account, and only a payload resource of it.
	segments := strings.Split(strings.Trim(source.EscapedPath(), "/"), "/")
	api := -1
	for index := range segments {
		if index+1 < len(segments) && segments[index] == "nms" && segments[index+1] == "v1" {
			api = index
		}
	}
	if api < 0 || len(segments) < api+7 || segments[api+4] != "objects" ||
		(segments[len(segments)-1] != "payload" && segments[len(segments)-2] != "payloadParts") {
		return nil, http.StatusBadRequest, errors.New("the URL is not a message store payload")
	}
	box, _ := url.PathUnescape(segments[api+3])
	if box != claims.MCDataID {
		return nil, http.StatusForbidden, errors.New("the file is not in the uploader's message store account")
	}
	root, found := "", false
	for _, candidate := range []string{svc.cfg.Endpoints.MsgStore, svc.cfg.Endpoints.MsgStoreInternal} {
		if candidate == "" {
			continue
		}
		base, err := url.Parse(candidate)
		if err == nil && base.Host == source.Host && strings.HasPrefix(source.Path, strings.TrimSuffix(base.Path, "/")+"/") {
			root, found = strings.TrimSuffix(base.Path, "/"), true
		}
	}
	internal := strings.TrimSuffix(svc.cfg.Endpoints.MsgStoreInternal, "/")
	if internal == "" {
		return nil, http.StatusBadRequest, errors.New("no message store is configured")
	}
	if !found {
		return nil, http.StatusForbidden, errors.New("the URL is not this system's message store")
	}
	target := internal + strings.TrimPrefix(source.EscapedPath(), root)
	fetchRequest, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	fetchRequest.Header.Set("Authorization", request.Header.Get("Authorization"))
	client := *svc.httpClient()
	client.Timeout = 10 * time.Second
	// A payload the store holds only by reference answers with a redirect: not followed.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(fetchRequest)
	if err != nil {
		return nil, http.StatusBadGateway, errors.New("the message store is unreachable")
	}
	defer closeQuietly(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, http.StatusConflict, fmt.Errorf("the message store answered %d", response.StatusCode)
	}
	name := path.Base(segments[api+5])
	if _, disposition, err := mime.ParseMediaType(response.Header.Get("Content-Disposition")); err == nil && disposition["filename"] != "" {
		name = disposition["filename"]
	}
	file, err := writeStoredFile(directory, name, response.Header.Get("Content-Type"), response.Body, limit)
	if errors.Is(err, errTooLarge) {
		return nil, http.StatusRequestEntityTooLarge, errors.New("file exceeds the configured maximum")
	}
	if err != nil {
		return nil, http.StatusInternalServerError, errors.New("storage unavailable")
	}
	return file, 0, nil
}

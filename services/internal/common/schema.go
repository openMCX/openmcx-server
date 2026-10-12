//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// XML Schema validation (libxml2) of the group, GMOP and user profile documents the GMS and the CMS accept.
//
// Specifications: TS 24.481 V19.3.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19), RFC 4825, OMA XDM (Group XDM),
// OMA PoC list service.
package common

// XML Schema validation of the documents the GMS and the CMS accept (RFC 4825
// section 8.2.5): group documents against the OMA list-service schema with the TS 24.481
// MCS extensions (TS 24.481 clause 7.2.4), GMOP documents against TS 24.481 clause 7.3.3,
// MCPTT user profile documents against TS 24.484 clause 8.3.2.3 and MCVideo user profile
// documents against TS 24.484 clause 9.3.2.3. libxml2 does the
// validation; the schemas are compiled once from the copies embedded below and
// never fetched: every schemaLocation, remote or relative, resolves to the
// embedded file of the same name, and any other external entity is refused.

/*
#cgo pkg-config: libxml-2.0
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlschemas.h>

typedef struct { const char *name; const char *text; } mcx_schema_file;
static mcx_schema_file *mcx_files;
static int mcx_nfiles;

static void mcx_set_files(mcx_schema_file *files, int count) { mcx_files = files; mcx_nfiles = count; }

// Every external resource libxml2 asks for is looked up by its last path
// segment among the embedded schema files; nothing is read from disk or network.
static xmlParserInputPtr mcx_loader(const char *url, const char *id, xmlParserCtxtPtr ctxt) {
  (void)id;
  if (!url) return NULL;
  const char *base = strrchr(url, '/');
  base = base ? base + 1 : url;
  for (int index = 0; index < mcx_nfiles; index++) {
    if (strcmp(mcx_files[index].name, base) == 0) {
      xmlParserInputPtr in = xmlNewStringInputStream(ctxt, (const xmlChar *)mcx_files[index].text);
      if (in) in->filename = (const char *)xmlStrdup((const xmlChar *)mcx_files[index].name);
      return in;
    }
  }
  return NULL;
}

static void mcx_init(void) {
  xmlInitParser();
  xmlSetExternalEntityLoader(mcx_loader);
}

typedef struct { char *buf; int len; int count; int line; } mcx_errors;

static void mcx_collect(void *data, xmlErrorPtr err) {
  mcx_errors *collected = (mcx_errors *)data;
  if (!err || err->level < XML_ERR_ERROR) return;
  if (collected->count++ == 0 && err->message) {
    snprintf(collected->buf, collected->len, "%s", err->message);
    size_t length = strlen(collected->buf);
    while (length > 0 && (collected->buf[length - 1] == '\n' || collected->buf[length - 1] == ' ')) collected->buf[--length] = 0;
    collected->line = err->line;
  }
}

static xmlSchemaPtr mcx_compile(const char *text, int len, char *msg, int msglen) {
  mcx_errors collected = {msg, msglen, 0, 0};
  xmlSchemaParserCtxtPtr parser = xmlSchemaNewMemParserCtxt(text, len);
  if (!parser) { snprintf(msg, msglen, "no schema parser context"); return NULL; }
  xmlSchemaSetParserStructuredErrors(parser, (xmlStructuredErrorFunc)mcx_collect, &collected);
  xmlSchemaPtr schema = xmlSchemaParse(parser);
  xmlSchemaFreeParserCtxt(parser);
  if (schema && collected.count > 0) { xmlSchemaFree(schema); return NULL; }
  return schema;
}

// mcx_validate returns 0 for a valid document, 1 for a schema violation and -1
// for a document libxml2 cannot parse.
static int mcx_validate(xmlSchemaPtr schema, const char *doc_text, int len, char *msg, int msglen, int *line) {
  mcx_errors collected = {msg, msglen, 0, 0};
  xmlDocPtr doc = xmlReadMemory(doc_text, len, "document.xml", NULL,
                                XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
  if (!doc) { snprintf(msg, msglen, "not a well-formed document"); return -1; }
  xmlSchemaValidCtxtPtr validator = xmlSchemaNewValidCtxt(schema);
  if (!validator) { xmlFreeDoc(doc); snprintf(msg, msglen, "no validation context"); return -1; }
  xmlSchemaSetValidStructuredErrors(validator, (xmlStructuredErrorFunc)mcx_collect, &collected);
  int rc = xmlSchemaValidateDoc(validator, doc);
  xmlSchemaFreeValidCtxt(validator);
  xmlFreeDoc(doc);
  *line = collected.line;
  if (rc == 0 && collected.count == 0) return 0;
  if (collected.count == 0) snprintf(msg, msglen, "the document does not conform to the schema");
  return 1;
}
*/
import "C"

import (
	"bytes"
	"embed"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"unicode/utf8"
	"unsafe"
)

//go:embed schemas/*.xsd
var schemaFS embed.FS

// ------------------------------------------------------------------------------
// Namespaces of the schemas (TS 24.481 table 7.2.2-2, TS 24.484 clause 8.3.2.4).
const (
	resourceListsNS   = "urn:ietf:params:xml:ns:resource-lists"
	omaCommonPolicyNS = "urn:oma:xml:xdm:common-policy"
	profileNS         = "urn:3gpp:mcptt:user-profile:1.0"
	mcdataProfileNS   = "urn:3gpp:ns:mcdata:user-profile:1.0"
	ueInitConfigNS    = "urn:3gpp:mcptt:mcpttUEinitConfig:1.0"
)

// ------------------------------------------------------------------------------
// Helper: a documentSchema validates one kind of document: the root element it must
// have, and the schemas it is composed from, imported in dependency order so
// that each namespace is loaded from its own file before a schema that imports it
// without a location.
type documentSchema struct {
	name    string
	root    xml.Name
	imports []schemaImport

	once     sync.Once
	mu       sync.Mutex
	compiled C.xmlSchemaPtr
	declared map[string]map[string]bool // namespace -> element names it declares
	err      error
}

// ------------------------------------------------------------------------------
// Helper: one schema of a documentSchema: its target namespace and embedded file.
type schemaImport struct{ namespace, file string }

// ------------------------------------------------------------------------------
// The schemas of the documents the GMS and the CMS validate.
var (
	groupSchemaImports = []schemaImport{
		{"http://www.w3.org/XML/1998/namespace", "xml.xsd"},
		{commonPolicyNS, "common-policy.xsd"},
		{resourceListsNS, "resource-lists.xsd"},
		{"urn:oma:xml:xdm:resource-list:oma-uriusage", "xdm_rsrclst_uriusage-V1_0.xsd"},
		{omaCommonPolicyNS, "xdm_commonPolicy-v1_0.xsd"},
		{xdmExtensionsNS, "xdm_extensions-v1_0.xsd"},
		{pocNS, "poc_listService-v1_0.xsd"},
		{mcpttgiNS, "mcptt-group-info.xsd"},
	}
	// TS 24.481 clause 7.2.4: the OMA group document schema with the MCS extensions.
	groupDocumentSchema = &documentSchema{name: "group document", root: xml.Name{Space: pocNS, Local: "group"},
		imports: groupSchemaImports}
	// TS 24.481 clause 7.3.3: the GMOP document.
	gmopDocumentSchema = &documentSchema{name: "GMOP document", root: xml.Name{Space: gmopNS, Local: "document"},
		imports: append(append([]schemaImport{}, groupSchemaImports...), schemaImport{gmopNS, "mcptt-gmop.xsd"})}
	// TS 24.484 clause 8.3.2.3, with the MCData user profile schema (TS 24.484 clause 10.3.2.3) for the
	// MCData actions a profile of this implementation carries in its ruleset.
	userProfileSchema = &documentSchema{name: "MCPTT user profile", root: xml.Name{Space: profileNS, Local: "mcptt-user-profile"},
		imports: []schemaImport{
			{"http://www.w3.org/XML/1998/namespace", "xml.xsd"},
			{commonPolicyNS, "common-policy.xsd"},
			{ueInitConfigNS, "ue-init-config.xsd"},
			{profileNS, "mcptt-user-profile.xsd"},
			{mcdataProfileNS, "mcdata-user-profile.xsd"},
		}}
	// TS 24.484 clause 10.3.2.3.
	mcdataProfileSchema = &documentSchema{name: "MCData user profile", root: xml.Name{Space: mcdataProfileNS, Local: "mcdata-user-profile"},
		imports: []schemaImport{
			{"http://www.w3.org/XML/1998/namespace", "xml.xsd"},
			{commonPolicyNS, "common-policy.xsd"},
			{ueInitConfigNS, "ue-init-config.xsd"},
			{mcdataProfileNS, "mcdata-user-profile.xsd"},
		}}
	// TS 24.484 clause 7.4.2.3.
	locationConfigSchema = &documentSchema{name: "location user configuration", root: xml.Name{Space: locationConfigNS, Local: "location-user-configuration-data"},
		imports: []schemaImport{
			{"http://www.w3.org/XML/1998/namespace", "xml.xsd"},
			{commonPolicyNS, "common-policy.xsd"},
			{locationConfigNS, "location-user-config.xsd"},
		}}
	// TS 24.484 clauses 8.4.2.3, 9.4.2.3 and 10.4.2.3: the service configuration documents.
	mcpttServiceConfigSchema   = serviceConfigSchema("MCPTT service configuration", mcpttServiceConfigNS, "mcptt-service-config.xsd")
	mcvideoServiceConfigSchema = serviceConfigSchema("MCVideo service configuration", mcvideoServiceConfigNS, "mcvideo-service-config.xsd")
	mcdataServiceConfigSchema  = serviceConfigSchema("MCData service configuration", mcdataServiceConfigNS, "mcdata-service-config.xsd")
	// TS 24.484 clause 9.3.2.3.
	mcvideoProfileSchema = &documentSchema{name: "MCVideo user profile", root: xml.Name{Space: mcvideoProfileNS, Local: "mcvideo-user-profile"},
		imports: []schemaImport{
			{"http://www.w3.org/XML/1998/namespace", "xml.xsd"},
			{commonPolicyNS, "common-policy.xsd"},
			{ueInitConfigNS, "ue-init-config.xsd"},
			{mcvideoProfileNS, "mcvideo-user-profile.xsd"},
		}}
)

// ------------------------------------------------------------------------------
// Helper: the schema of a service configuration document (root <service-configuration-info>).
func serviceConfigSchema(name, namespace, file string) *documentSchema {
	return &documentSchema{name: name, root: xml.Name{Space: namespace, Local: "service-configuration-info"},
		imports: []schemaImport{{"http://www.w3.org/XML/1998/namespace", "xml.xsd"}, {namespace, file}}}
}

// ------------------------------------------------------------------------------
// RFC 4825 section 8.2.5: schemaViolation is a document that fails its schema:
// <schema-validation-error>.
type schemaViolation struct {
	Line   int
	Reason string
}

// ------------------------------------------------------------------------------
// Helper: the violation with its line, when known.
func (violation *schemaViolation) Error() string {
	if violation.Line > 0 {
		return fmt.Sprintf("line %d: %s", violation.Line, violation.Reason)
	}
	return violation.Reason
}

// ------------------------------------------------------------------------------
// RFC 4825 section 8.2.2: errNotWellFormed marks a body that is not XML at all (<not-well-formed>).
var errNotWellFormed = errors.New("not a well-formed XML document")

// RFC 4825 section 8.2.2: errNotUTF8 marks a body that is not UTF-8 (<not-utf-8>).
var errNotUTF8 = errors.New("the document is not encoded in UTF-8")

// Helper: the embedded schema files, loaded once.
var (
	schemaFilesOnce sync.Once
	schemaFilesErr  error
	schemaTexts     map[string]string
)

// ------------------------------------------------------------------------------
// Helper: loadSchemaFiles hands the embedded schema files to the libxml2 entity loader.
// The C copies live as long as the process.
func loadSchemaFiles() error {
	schemaFilesOnce.Do(func() {
		entries, err := fs.ReadDir(schemaFS, "schemas")
		if err != nil {
			schemaFilesErr = err
			return
		}
		files := unsafe.Slice((*C.mcx_schema_file)(C.malloc(C.size_t(len(entries))*C.size_t(unsafe.Sizeof(C.mcx_schema_file{})))), len(entries))
		schemaTexts = map[string]string{}
		for index, entry := range entries {
			raw, err := schemaFS.ReadFile("schemas/" + entry.Name())
			if err != nil {
				schemaFilesErr = err
				return
			}
			schemaTexts[entry.Name()] = string(raw)
			files[index] = C.mcx_schema_file{name: C.CString(entry.Name()), text: C.CString(string(raw))}
		}
		C.mcx_set_files(&files[0], C.int(len(entries)))
		C.mcx_init()
	})
	return schemaFilesErr
}

// ------------------------------------------------------------------------------
// Helper: compiles the schema once from its imports, and lists the element names each namespace declares.
func (schema *documentSchema) load() error {
	schema.once.Do(func() {
		if schema.err = loadSchemaFiles(); schema.err != nil {
			return
		}
		var driver strings.Builder
		driver.WriteString(`<?xml version="1.0" encoding="UTF-8"?><xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">`)
		schema.declared = map[string]map[string]bool{}
		for _, imp := range schema.imports {
			driver.WriteString(`<xs:import namespace="` + imp.namespace + `" schemaLocation="` + imp.file + `"/>`)
			names, err := declaredElements(schemaTexts[imp.file])
			if err != nil {
				schema.err = fmt.Errorf("%s: %w", imp.file, err)
				return
			}
			schema.declared[imp.namespace] = names
		}
		driver.WriteString(`</xs:schema>`)
		text := C.CString(driver.String())
		defer C.free(unsafe.Pointer(text))
		msg := (*C.char)(C.malloc(512))
		defer C.free(unsafe.Pointer(msg))
		schema.compiled = C.mcx_compile(text, C.int(driver.Len()), msg, 512)
		if schema.compiled == nil {
			schema.err = fmt.Errorf("the %s schema does not compile: %s", schema.name, C.GoString(msg))
		}
	})
	return schema.err
}

// ------------------------------------------------------------------------------
// Helper: declaredElements lists the element names a schema declares, at any level.
func declaredElements(text string) (map[string]bool, error) {
	names := map[string]bool{}
	decoder := xml.NewDecoder(strings.NewReader(text))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Space == "http://www.w3.org/2001/XMLSchema" && start.Name.Local == "element" {
			for _, attr := range start.Attr {
				if attr.Name.Local == "name" {
					names[attr.Value] = true
				}
			}
		}
	}
}

// ------------------------------------------------------------------------------
// RFC 4825 section 8.2.2 and section 8.2.5: validate checks a document against the schema. It returns errNotWellFormed,
// a *schemaViolation, or nil.
func (schema *documentSchema) validate(raw []byte) error {
	if err := schema.load(); err != nil {
		return err
	}
	if !utf8.Valid(raw) {
		return errNotUTF8
	}
	if bytes.Contains(raw, []byte("<!DOCTYPE")) || bytes.Contains(raw, []byte("<!ENTITY")) {
		return errNotWellFormed
	}
	root, err := parseXMLTree(raw)
	if err != nil {
		return errNotWellFormed
	}
	if root.Name != schema.root {
		return &schemaViolation{Reason: fmt.Sprintf("the root element is {%s}%s, not the <%s> of a %s", root.Name.Space, root.Name.Local, schema.root.Local, schema.name)}
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		return &schemaViolation{Reason: "document size out of range"}
	}
	text := C.CBytes(raw)
	defer C.free(text)
	msg := (*C.char)(C.malloc(512))
	defer C.free(unsafe.Pointer(msg))
	var line C.int
	schema.mu.Lock()
	rc := C.mcx_validate(schema.compiled, (*C.char)(text), C.int(len(raw)), msg, 512, &line)
	schema.mu.Unlock()
	switch rc {
	case -1:
		return errNotWellFormed
	case 1:
		return &schemaViolation{Line: int(line), Reason: C.GoString(msg)}
	}
	// RFC 4825 section 8.2.5: an element of a namespace the server understands, which the
	// schema's wildcards admitted but the schema does not declare, is refused.
	if name, ok := schema.undeclared(root); ok {
		return &schemaViolation{Reason: fmt.Sprintf("element <%s> is not defined in the schema of namespace %s", name.Local, name.Space)}
	}
	return nil
}

// ------------------------------------------------------------------------------
// RFC 4825 section 8.2.5: the first element of a namespace the schema knows that the schema does not declare.
func (schema *documentSchema) undeclared(node *xmlNode) (xml.Name, bool) {
	if names, known := schema.declared[node.Name.Space]; known && !names[node.Name.Local] {
		return node.Name, true
	}
	for _, childNode := range node.Children {
		if name, ok := schema.undeclared(childNode); ok {
			return name, true
		}
	}
	return xml.Name{}, false
}

// ------------------------------------------------------------------------------
// RFC 4825 section 11: schemaError maps a validation result to the detailed conflict report.
func schemaError(err error) error {
	var violation *schemaViolation
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errNotUTF8):
		return xcapFail(409, "not-utf-8", err.Error())
	case errors.Is(err, errNotWellFormed):
		return xcapFail(409, "not-well-formed", "the document is not well-formed XML")
	case errors.As(err, &violation):
		return xcapFail(409, "schema-validation-error", violation.Error())
	}
	return xcapFail(500, "", err.Error())
}

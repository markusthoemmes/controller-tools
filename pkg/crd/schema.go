/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package crd

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	crdmarkers "sigs.k8s.io/controller-tools/pkg/crd/markers"

	"sigs.k8s.io/controller-tools/pkg/loader"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

// Schema flattening is done in a recursive mapping method.
// Start reading at infoToSchema.

const (
	// defPrefix is the prefix used to link to definitions in the OpenAPI schema.
	defPrefix = "#/definitions/"
)

var (
	// byteType is the types.Type for byte (see the types documention
	// for why we need to look this up in the Universe), saved
	// for quick comparison.
	byteType = types.Universe.Lookup("byte").Type()
)

// SchemaMarker is any marker that needs to modify the schema of the underlying type or field.
type SchemaMarker interface {
	// ApplyToSchema is called after the rest of the schema for a given type
	// or field is generated, to modify the schema appropriately.
	ApplyToSchema(*apiext.JSONSchemaProps) error
}

// applyFirstMarker is applied before any other markers.  It's a bit of a hack.
type applyFirstMarker interface {
	ApplyFirst()
}

// schemaRequester knows how to marker that another schema (e.g. via an external reference) is necessary.
type schemaRequester interface {
	NeedSchemaFor(typ TypeIdent)
}

// schemaContext stores and provides information across a hierarchy of schema generation.
type schemaContext struct {
	pkg  *loader.Package
	info *markers.TypeInfo

	schemaRequester schemaRequester
	PackageMarkers  markers.MarkerValues

	allowDangerousTypes bool
}

// newSchemaContext constructs a new schemaContext for the given package and schema requester.
// It must have type info added before use via ForInfo.
func newSchemaContext(pkg *loader.Package, req schemaRequester, allowDangerousTypes bool) *schemaContext {
	pkg.NeedTypesInfo()
	return &schemaContext{
		pkg:                 pkg,
		schemaRequester:     req,
		allowDangerousTypes: allowDangerousTypes,
	}
}

// ForInfo produces a new schemaContext with containing the same information
// as this one, except with the given type information.
func (c *schemaContext) ForInfo(info *markers.TypeInfo) *schemaContext {
	return &schemaContext{
		pkg:                 c.pkg,
		info:                info,
		schemaRequester:     c.schemaRequester,
		allowDangerousTypes: c.allowDangerousTypes,
	}
}

// requestSchema asks for the schema for a type in the package with the
// given import path.
func (c *schemaContext) requestSchema(pkgPath, typeName string) {
	pkg := c.pkg
	if pkgPath != "" {
		pkg = c.pkg.Imports()[pkgPath]
	}
	c.schemaRequester.NeedSchemaFor(TypeIdent{
		Package: pkg,
		Name:    typeName,
	})
}

// infoToSchema creates a schema for the type in the given set of type information.
func infoToSchema(ctx *schemaContext) *apiext.JSONSchemaProps {
	return typeToSchema(ctx, ctx.info.RawSpec.Type)
}

// applyMarkers applies schema markers to the given schema, respecting "apply first" markers.
func applyMarkers(ctx *schemaContext, markerSet markers.MarkerValues, props *apiext.JSONSchemaProps, node ast.Node) {
	// apply "apply first" markers first...
	for _, markerValues := range markerSet {
		for _, markerValue := range markerValues {
			if _, isApplyFirst := markerValue.(applyFirstMarker); !isApplyFirst {
				continue
			}

			schemaMarker, isSchemaMarker := markerValue.(SchemaMarker)
			if !isSchemaMarker {
				continue
			}

			if err := schemaMarker.ApplyToSchema(props); err != nil {
				ctx.pkg.AddError(loader.ErrFromNode(err /* an okay guess */, node))
			}
		}
	}

	// ...then the rest of the markers
	for _, markerValues := range markerSet {
		for _, markerValue := range markerValues {
			if _, isApplyFirst := markerValue.(applyFirstMarker); isApplyFirst {
				// skip apply-first markers, which were already applied
				continue
			}

			schemaMarker, isSchemaMarker := markerValue.(SchemaMarker)
			if !isSchemaMarker {
				continue
			}
			if err := schemaMarker.ApplyToSchema(props); err != nil {
				ctx.pkg.AddError(loader.ErrFromNode(err /* an okay guess */, node))
			}
		}
	}
}

// typeToSchema creates a schema for the given AST type.
func typeToSchema(ctx *schemaContext, rawType ast.Expr) *apiext.JSONSchemaProps {
	var props *apiext.JSONSchemaProps
	switch expr := rawType.(type) {
	case *ast.Ident:
		props = localNamedToSchema(ctx, expr)
	case *ast.SelectorExpr:
		props = namedToSchema(ctx, expr)
	case *ast.ArrayType:
		props = arrayToSchema(ctx, expr)
	case *ast.MapType:
		props = mapToSchema(ctx, expr)
	case *ast.StarExpr:
		props = typeToSchema(ctx, expr.X)
	case *ast.StructType:
		props = structToSchema(ctx, expr)
	default:
		ctx.pkg.AddError(loader.ErrFromNode(fmt.Errorf("unsupported AST kind %T", expr), rawType))
		// NB(directxman12): we explicitly don't handle interfaces
		return &apiext.JSONSchemaProps{}
	}

	props.Description = ctx.info.Doc

	applyMarkers(ctx, ctx.info.Markers, props, rawType)

	return props
}

// qualifiedName constructs a JSONSchema-safe qualified name for a type
// (`<typeName>` or `<safePkgPath>~0<typeName>`, where `<safePkgPath>`
// is the package path with `/` replaced by `~1`, according to JSONPointer
// escapes).
func qualifiedName(pkgName, typeName string) string {
	if pkgName != "" {
		return strings.Replace(pkgName, "/", "~1", -1) + "~0" + typeName
	}
	return typeName
}

// TypeRefLink creates a definition link for the given type and package.
func TypeRefLink(pkgName, typeName string) string {
	return defPrefix + qualifiedName(pkgName, typeName)
}

// localNamedToSchema creates a schema (ref) for a *potentially* local type reference
// (could be external from a dot-import).
func localNamedToSchema(ctx *schemaContext, ident *ast.Ident) *apiext.JSONSchemaProps {
	typeInfo := ctx.pkg.TypesInfo.TypeOf(ident)
	if typeInfo == types.Typ[types.Invalid] {
		ctx.pkg.AddError(loader.ErrFromNode(fmt.Errorf("unknown type %s", ident.Name), ident))
		return &apiext.JSONSchemaProps{}
	}
	if basicInfo, isBasic := typeInfo.(*types.Basic); isBasic {
		typ, fmt, err := builtinToType(basicInfo, ctx.allowDangerousTypes)
		if err != nil {
			ctx.pkg.AddError(loader.ErrFromNode(err, ident))
		}
		return &apiext.JSONSchemaProps{
			Type:   typ,
			Format: fmt,
		}
	}
	// NB(directxman12): if there are dot imports, this might be an external reference,
	// so use typechecking info to get the actual object
	typeNameInfo := typeInfo.(*types.Named).Obj()
	pkg := typeNameInfo.Pkg()
	pkgPath := loader.NonVendorPath(pkg.Path())
	if pkg == ctx.pkg.Types {
		pkgPath = ""
	}
	ctx.requestSchema(pkgPath, typeNameInfo.Name())
	link := TypeRefLink(pkgPath, typeNameInfo.Name())
	return &apiext.JSONSchemaProps{
		Ref: &link,
	}
}

// namedSchema creates a schema (ref) for an explicitly external type reference.
func namedToSchema(ctx *schemaContext, named *ast.SelectorExpr) *apiext.JSONSchemaProps {
	typeInfoRaw := ctx.pkg.TypesInfo.TypeOf(named)
	if typeInfoRaw == types.Typ[types.Invalid] {
		ctx.pkg.AddError(loader.ErrFromNode(fmt.Errorf("unknown type %v.%s", named.X, named.Sel.Name), named))
		return &apiext.JSONSchemaProps{}
	}
	typeInfo := typeInfoRaw.(*types.Named)
	typeNameInfo := typeInfo.Obj()
	nonVendorPath := loader.NonVendorPath(typeNameInfo.Pkg().Path())
	ctx.requestSchema(nonVendorPath, typeNameInfo.Name())
	link := TypeRefLink(nonVendorPath, typeNameInfo.Name())
	return &apiext.JSONSchemaProps{
		Ref: &link,
	}
	// NB(directxman12): we special-case things like resource.Quantity during the "collapse" phase.
}

// arrayToSchema creates a schema for the items of the given array, dealing appropriately
// with the special `[]byte` type (according to OpenAPI standards).
func arrayToSchema(ctx *schemaContext, array *ast.ArrayType) *apiext.JSONSchemaProps {
	eltType := ctx.pkg.TypesInfo.TypeOf(array.Elt)
	if eltType == byteType && array.Len == nil {
		// byte slices are represented as base64-encoded strings
		// (the format is defined in OpenAPI v3, but not JSON Schema)
		return &apiext.JSONSchemaProps{
			Type:   "string",
			Format: "byte",
		}
	}
	// TODO(directxman12): backwards-compat would require access to markers from base info
	items := typeToSchema(ctx.ForInfo(&markers.TypeInfo{}), array.Elt)

	return &apiext.JSONSchemaProps{
		Type:  "array",
		Items: &apiext.JSONSchemaPropsOrArray{Schema: items},
	}
}

// mapToSchema creates a schema for items of the given map.  Key types must eventually resolve
// to string (other types aren't allowed by JSON, and thus the kubernetes API standards).
func mapToSchema(ctx *schemaContext, mapType *ast.MapType) *apiext.JSONSchemaProps {
	keyInfo := ctx.pkg.TypesInfo.TypeOf(mapType.Key)
	// check that we've got a type that actually corresponds to a string
	for keyInfo != nil {
		switch typedKey := keyInfo.(type) {
		case *types.Basic:
			if typedKey.Info()&types.IsString == 0 {
				ctx.pkg.AddError(loader.ErrFromNode(fmt.Errorf("map keys must be strings, not %s", keyInfo.String()), mapType.Key))
				return &apiext.JSONSchemaProps{}
			}
			keyInfo = nil // stop iterating
		case *types.Named:
			keyInfo = typedKey.Underlying()
		default:
			ctx.pkg.AddError(loader.ErrFromNode(fmt.Errorf("map keys must be strings, not %s", keyInfo.String()), mapType.Key))
			return &apiext.JSONSchemaProps{}
		}
	}

	// TODO(directxman12): backwards-compat would require access to markers from base info
	var valSchema *apiext.JSONSchemaProps
	switch val := mapType.Value.(type) {
	case *ast.Ident:
		valSchema = localNamedToSchema(ctx.ForInfo(&markers.TypeInfo{}), val)
	case *ast.SelectorExpr:
		valSchema = namedToSchema(ctx.ForInfo(&markers.TypeInfo{}), val)
	case *ast.ArrayType:
		valSchema = arrayToSchema(ctx.ForInfo(&markers.TypeInfo{}), val)
		if valSchema.Type == "array" && valSchema.Items.Schema.Type != "string" {
			ctx.pkg.AddError(loader.ErrFromNode(fmt.Errorf("map values must be a named type, not %T", mapType.Value), mapType.Value))
			return &apiext.JSONSchemaProps{}
		}
	case *ast.StarExpr:
		valSchema = typeToSchema(ctx.ForInfo(&markers.TypeInfo{}), val)
	default:
		ctx.pkg.AddError(loader.ErrFromNode(fmt.Errorf("map values must be a named type, not %T", mapType.Value), mapType.Value))
		return &apiext.JSONSchemaProps{}
	}

	return &apiext.JSONSchemaProps{
		Type: "object",
		AdditionalProperties: &apiext.JSONSchemaPropsOrBool{
			Schema: valSchema,
			Allows: true, /* set automatically by serialization, but useful for testing */
		},
	}
}

type schemaOverrides struct {
	forceOptional bool
	description   string
}

// Preserve unknown fields for a few types to allow for proper validation.
var perserveUnknownOverrides = map[string]bool{
	"k8s.io/api/core/v1.PodSpec":         true,
	"k8s.io/api/core/v1.Container":       true,
	"k8s.io/api/core/v1.HTTPGetAction":   true,
	"k8s.io/api/core/v1.TCPSocketAction": true,
	"k8s.io/api/core/v1.ContainerPort":   true,

	// Allow extra fields as features
	"k8s.io/api/core/v1.SecurityContext": true,
	"k8s.io/api/core/v1.EnvVarSource":    true,
}

var allowedFields = map[string]map[string]schemaOverrides{
	"k8s.io/api/core/v1.Volume": {
		"Name":         {},
		"VolumeSource": {},
	},
	"k8s.io/api/core/v1.VolumeSource": {
		"Secret":    {},
		"ConfigMap": {},
		"Projected": {},
	},
	"k8s.io/api/core/v1.VolumeProjection": {
		"Secret":              {},
		"ConfigMap":           {},
		"ServiceAccountToken": {},
	},
	"k8s.io/api/core/v1.ConfigMapProjection": {
		"LocalObjectReference": {},
		"Items":                {},
		"Optional":             {},
	},
	"k8s.io/api/core/v1.SecretProjection": {
		"LocalObjectReference": {},
		"Items":                {},
		"Optional":             {},
	},
	"k8s.io/api/core/v1.ServiceAccountTokenProjection": {
		"Audience":          {},
		"ExpirationSeconds": {},
		"Path":              {},
	},
	"k8s.io/api/core/v1.KeyToPath": {
		"Key":  {},
		"Path": {},
		"Mode": {},
	},
	"k8s.io/api/core/v1.PodSpec": {
		"ServiceAccountName": {},
		"Containers":         {},
		"Volumes":            {},
		"ImagePullSecrets":   {},
		"EnableServiceLinks": {},
		// Features
		//"Affinity":        {},
		//"HostAliases":     {},
		//"NodeSelector":    {},
		//"Tolerations":     {},
		//"SecurityContext": {},
	},
	"k8s.io/api/core/v1.Container": {
		"Name":                     {forceOptional: true},
		"Args":                     {},
		"Command":                  {},
		"Env":                      {},
		"WorkingDir":               {},
		"EnvFrom":                  {},
		"Image":                    {},
		"ImagePullPolicy":          {},
		"LivenessProbe":            {},
		"Ports":                    {forceOptional: true},
		"ReadinessProbe":           {},
		"Resources":                {},
		"SecurityContext":          {},
		"TerminationMessagePath":   {},
		"TerminationMessagePolicy": {},
		"VolumeMounts":             {},
	},
	"k8s.io/api/core/v1.VolumeMount": {
		"Name":      {},
		"ReadOnly":  {},
		"MountPath": {},
		"SubPath":   {},
	},
	"k8s.io/api/core/v1.Probe": {
		"Handler":             {},
		"InitialDelaySeconds": {},
		"TimeoutSeconds":      {},
		"PeriodSeconds": {
			description: "How often (in seconds) to perform the probe.",
		},
		"SuccessThreshold": {},
		"FailureThreshold": {},
	},
	"k8s.io/api/core/v1.Handler": {
		"Exec":      {},
		"HTTPGet":   {},
		"TCPSocket": {},
	},
	"k8s.io/api/core/v1.ExecAction": {
		"Command": {},
	},
	"k8s.io/api/core/v1.HTTPGetAction": {
		"Host":        {},
		"Path":        {},
		"Scheme":      {},
		"HTTPHeaders": {},
	},
	"k8s.io/api/core/v1.TCPSocketAction": {
		"Host": {},
	},
	"k8s.io/api/core/v1.ContainerPort": {
		"ContainerPort": {},
		"Name":          {},
		"Protocol":      {},
	},
	"k8s.io/api/core/v1.EnvVar": {
		"Name":      {},
		"Value":     {},
		"ValueFrom": {},
	},
	"k8s.io/api/core/v1.EnvVarSource": {
		"ConfigMapKeyRef": {},
		"SecretKeyRef":    {},
		// Features
		//"FieldRef":         {},
		//"ResourceFieldRef": {},
	},
	"k8s.io/api/core/v1.LocalObjectReference": {
		"Name": {},
	},
	"k8s.io/api/core/v1.ConfigMapKeySelectorMask": {
		"Key":                  {},
		"Optional":             {},
		"LocalObjectReference": {},
	},
	"k8s.io/api/core/v1.SecretKeySelectorMask": {
		"Key":                  {},
		"Optional":             {},
		"LocalObjectReference": {},
	},
	"k8s.io/api/core/v1.ConfigMapEnvSource": {
		"Optional":             {},
		"LocalObjectReference": {},
	},
	"k8s.io/api/core/v1.SecretEnvSource": {
		"Optional":             {},
		"LocalObjectReference": {},
	},
	"k8s.io/api/core/v1.EnvFromSource": {
		"Prefix":       {},
		"ConfigMapRef": {},
		"SecretRef":    {},
	},
	"k8s.io/api/core/v1.ResourceRequirementsMask": {
		"Limits":   {},
		"Requests": {},
	},
	"k8s.io/api/core/v1.PodSecurityContext": {
		"RunAsUser":          {},
		"RunAsGroup":         {},
		"RunAsNonRoot":       {},
		"FSGroup":            {},
		"SupplementalGroups": {},
	},
	"k8s.io/api/core/v1.SecurityContext": {
		"RunAsUser":              {},
		"ReadOnlyRootFilesystem": {},
		"Capabilities":           {},
		// Features
		//"RunAsGroup":   {},
		//"RunAsNonRoot": {},
	},
	"k8s.io/api/core/v1.Capabilities": {
		"Drop": {},
	},
	"k8s.io/api/core/v1.ObjectReference": {
		"APIVersion": {},
		"Kind":       {},
		"Name":       {},
	},
}

// structToSchema creates a schema for the given struct.  Embedded fields are placed in AllOf,
// and can be flattened later with a Flattener.
func structToSchema(ctx *schemaContext, structType *ast.StructType) *apiext.JSONSchemaProps {
	props := &apiext.JSONSchemaProps{
		Type:       "object",
		Properties: make(map[string]apiext.JSONSchemaProps),
	}

	if ctx.info.RawSpec.Type != structType {
		ctx.pkg.AddError(loader.ErrFromNode(fmt.Errorf("encountered non-top-level struct (possibly embedded), those aren't allowed"), structType))
		return props
	}

	typN := ctx.pkg.ID + "." + ctx.info.RawSpec.Name.String()
	allowedFields := allowedFields[typN]
	for _, field := range ctx.info.Fields {
		fieldN := field.Name
		if fieldN == "" {
			// This is an embedded type. It may either be a pointer type or a direct
			// identifier. We take it's type name as field name since that's what Golang
			// struct construction essentially comes down to.
			if selector, ok := field.RawField.Type.(*ast.SelectorExpr); ok {
				fieldN = selector.Sel.Name
			} else if ident, ok := field.RawField.Type.(*ast.Ident); ok {
				fieldN = ident.Name
			} else {
				ctx.pkg.AddError(loader.ErrFromNode(fmt.Errorf("encountered unexpected embedded type"), field.RawField))
				return props
			}
		}

		var overrides schemaOverrides
		if allowedFields != nil {
			if o, ok := allowedFields[fieldN]; !ok {
				continue
			} else {
				overrides = o
			}
		}

		jsonTag, hasTag := field.Tag.Lookup("json")
		if !hasTag {
			// if the field doesn't have a JSON tag, it doesn't belong in output (and shouldn't exist in a serialized type)
			ctx.pkg.AddError(loader.ErrFromNode(fmt.Errorf("encountered struct field %q without JSON tag in type %q", field.Name, ctx.info.Name), field.RawField))
			continue
		}
		jsonOpts := strings.Split(jsonTag, ",")
		if len(jsonOpts) == 1 && jsonOpts[0] == "-" {
			// skipped fields have the tag "-" (note that "-," means the field is named "-")
			continue
		}

		inline := false
		omitEmpty := false
		for _, opt := range jsonOpts[1:] {
			switch opt {
			case "inline":
				inline = true
			case "omitempty":
				omitEmpty = true
			}
		}
		fieldName := jsonOpts[0]
		inline = inline || fieldName == "" // anonymous fields are inline fields in YAML/JSON

		// if no default required mode is set, default to required
		defaultMode := "required"
		if ctx.PackageMarkers.Get("kubebuilder:validation:Optional") != nil || overrides.forceOptional {
			defaultMode = "optional"
		}

		switch defaultMode {
		// if this package isn't set to optional default...
		case "required":
			// ...everything that's not inline, omitempty, or explicitly optional is required
			if !inline && !omitEmpty && field.Markers.Get("kubebuilder:validation:Optional") == nil && field.Markers.Get("optional") == nil {
				props.Required = append(props.Required, fieldName)
			}

		// if this package isn't set to required default...
		case "optional":
			// ...everything that isn't explicitly required is optional
			if field.Markers.Get("kubebuilder:validation:Required") != nil {
				props.Required = append(props.Required, fieldName)
			}
		}

		var propSchema *apiext.JSONSchemaProps
		if field.Markers.Get(crdmarkers.SchemalessName) != nil {
			propSchema = &apiext.JSONSchemaProps{}
		} else {
			propSchema = typeToSchema(ctx.ForInfo(&markers.TypeInfo{}), field.RawField.Type)
		}

		if overrides.description != "" {
			propSchema.Description = overrides.description
		} else {
			propSchema.Description = field.Doc
		}

		applyMarkers(ctx, field.Markers, propSchema, field.RawField)

		if inline {
			props.AllOf = append(props.AllOf, *propSchema)
			continue
		}

		props.Properties[fieldName] = *propSchema
	}

	if preserveUnknown, ok := perserveUnknownOverrides[typN]; ok {
		props.XPreserveUnknownFields = &preserveUnknown
	}

	return props
}

// builtinToType converts builtin basic types to their equivalent JSON schema form.
// It *only* handles types allowed by the kubernetes API standards. Floats are not
// allowed unless allowDangerousTypes is true
func builtinToType(basic *types.Basic, allowDangerousTypes bool) (typ string, format string, err error) {
	// NB(directxman12): formats from OpenAPI v3 are slightly different than those defined
	// in JSONSchema.  This'll use the OpenAPI v3 ones, since they're useful for bounding our
	// non-string types.
	basicInfo := basic.Info()
	switch {
	case basicInfo&types.IsBoolean != 0:
		typ = "boolean"
	case basicInfo&types.IsString != 0:
		typ = "string"
	case basicInfo&types.IsInteger != 0:
		typ = "integer"
	case basicInfo&types.IsFloat != 0 && allowDangerousTypes:
		typ = "number"
	default:
		// NB(directxman12): floats are *NOT* allowed in kubernetes APIs
		return "", "", fmt.Errorf("unsupported type %q", basic.String())
	}

	switch basic.Kind() {
	case types.Int32, types.Uint32:
		format = "int32"
	case types.Int64, types.Uint64:
		format = "int64"
	}

	return typ, format, nil
}

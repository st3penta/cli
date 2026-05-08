package sigstore_attestation_only

import rego.v1

# METADATA
# custom:
#   short_name: valid
deny contains result if {
	some error in _errors
	result := {"code": "sigstore_attestation_only.valid", "msg": error}
}

_errors contains error if {
	not _image_ref
	error := "input.image.ref not set"
}

_errors contains error if {
	not _sigstore_opts
	error := "default sigstore options not set"
}

_errors contains error if {
	info := ec.sigstore.verify_attestation(_image_ref, _sigstore_opts)
	some raw_error in info.errors
	error := sprintf("image attestation verification failed: %s", [raw_error])
}

_errors contains error if {
	info := ec.sigstore.verify_attestation(_image_ref, _sigstore_opts)
	count(info.attestations) == 0
	error := "verification successful, but no attestations found"
}

_errors contains error if {
	info := ec.sigstore.verify_attestation(_image_ref, _sigstore_opts)
	some att in info.attestations
	count(att.signatures) == 0
	error := sprintf("attestation has no signatures: %s", [att])
}

_errors contains error if {
	info := ec.sigstore.verify_attestation(_image_ref, _sigstore_opts)
	some att in info.attestations

	not _is_supported_slsa_predicate(att.statement.predicateType)
	error := sprintf("unexpected statement predicate: %s", [att.statement.predicateType])
}

_errors contains error if {
	info := ec.sigstore.verify_attestation(_image_ref, _sigstore_opts)
	some att in info.attestations
	builder_id := _builder_id(att)
	builder_id != "https://tekton.dev/chains/v2"
	error := sprintf("unexpected builder ID: %s", [builder_id])
}

_image_ref := input.image.ref

_sigstore_opts := data.config.default_sigstore_opts

_builder_id(att) := value if {
	value := att.statement.predicate.builder.id
} else := value if {
	value := att.statement.predicate.runDetails.builder.id
} else := "MISSING"

_is_supported_slsa_predicate(predicate_type) if {
	predicate_type == "https://slsa.dev/provenance/v0.2"
}

_is_supported_slsa_predicate(predicate_type) if {
	predicate_type == "https://slsa.dev/provenance/v1"
}

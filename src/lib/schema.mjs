import fs from "node:fs";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { runtimePaths } from "./paths.mjs";

const validators = new Map();

function validatorFor(schemaName, paths) {
  const key = `${paths.repo}:${schemaName}`;
  if (validators.has(key)) return validators.get(key);
  const schemaFile = path.join(paths.repo, "schemas", schemaName);
  const schema = JSON.parse(fs.readFileSync(schemaFile, "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictTypes: false, $data: false });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  validators.set(key, validate);
  return validate;
}

export function validateDocument(value, schemaName, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const validate = validatorFor(schemaName, paths);
  const ok = validate(value);
  return {
    ok: Boolean(ok),
    errors: ok
      ? []
      : (validate.errors || []).map((error) => `${error.instancePath || "/"} ${error.message}`)
  };
}

export function assertValidDocument(value, schemaName, options = {}) {
  const result = validateDocument(value, schemaName, options);
  if (!result.ok) throw new Error(`${schemaName} validation failed: ${result.errors.join("; ")}`);
  return value;
}

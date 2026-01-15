// Schema Validator - Strict validation with fail-closed behavior

/* eslint-disable @typescript-eslint/no-explicit-any */
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { auditorInputSchema } from '../schemas/input.schema.js';
import { auditorOutputSchema } from '../schemas/output.schema.js';
import type { AuditorInput, AuditorOutput } from '../types/events.js';

export class ValidationError extends Error {
  public readonly errors: unknown[];

  constructor(message: string, errors: unknown[]) {
    super(message);
    this.name = 'ValidationError';
    this.errors = errors;
  }
}

export class SchemaValidator {
  private ajv: any;
  private validateInput: any;
  private validateOutput: any;

  constructor() {
    // Handle ESM/CJS interop
    const AjvClass = (Ajv as any).default ?? Ajv;
    const addFormatsFunc = (addFormats as any).default ?? addFormats;

    this.ajv = new AjvClass({
      strict: true,
      allErrors: true,
      verbose: true
    });
    addFormatsFunc(this.ajv);

    this.validateInput = this.ajv.compile(auditorInputSchema);
    this.validateOutput = this.ajv.compile(auditorOutputSchema);
  }

  // Fail-closed: throws on invalid input
  assertValidInput(data: unknown): asserts data is AuditorInput {
    if (!this.validateInput(data)) {
      throw new ValidationError(
        'Input validation failed',
        this.validateInput.errors ?? []
      );
    }
  }

  // Fail-closed: throws on invalid output
  assertValidOutput(data: unknown): asserts data is AuditorOutput {
    if (!this.validateOutput(data)) {
      throw new ValidationError(
        'Output validation failed',
        this.validateOutput.errors ?? []
      );
    }
  }

  isValidInput(data: unknown): data is AuditorInput {
    return this.validateInput(data) as boolean;
  }

  isValidOutput(data: unknown): data is AuditorOutput {
    return this.validateOutput(data) as boolean;
  }

  getInputErrors(data: unknown): unknown[] {
    this.validateInput(data);
    return this.validateInput.errors ?? [];
  }

  getOutputErrors(data: unknown): unknown[] {
    this.validateOutput(data);
    return this.validateOutput.errors ?? [];
  }
}

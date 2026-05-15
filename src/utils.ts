import * as core from '@actions/core'

// A sha256 digest is 'sha256:' (7) + 64 hex chars = 71 chars total.
export const SHA256_DIGEST_LENGTH = 'sha256:'.length + 64

/**
 * Recover the parent image digest from a cosign/sigstore referrer tag.
 *
 * Referrer tags follow the convention `sha256-<64 hex>.<suffix>` where the
 * suffix is `.sig`, `.att`, `.sbom`, etc. The parent digest is the 71-char
 * `sha256:<64 hex>` string after replacing the `sha256-` prefix and stripping
 * the suffix.
 *
 * Returns null if the tag doesn't match the expected referrer format.
 */
export function parentDigestFromReferrerTag(tag: string): string | null {
  if (!tag.startsWith('sha256-')) return null
  const digest = `sha256:${tag.slice('sha256-'.length)}`
  if (digest.length < SHA256_DIGEST_LENGTH) return null
  return digest.slice(0, SHA256_DIGEST_LENGTH)
}

export function parseChallenge(challenge: string): Map<string, string> {
  const attributes = new Map<string, string>()
  if (challenge.startsWith('Bearer ')) {
    challenge = challenge.replace('Bearer ', '')
    const parts = challenge.split(',')
    for (const part of parts) {
      // Split on the first '=' only — values may legitimately contain '='
      // (e.g. base64-encoded scopes from some token services).
      const idx = part.indexOf('=')
      if (idx > 0) {
        const key = part.substring(0, idx)
        let value = part.substring(idx + 1)
        if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
          value = value.substring(1, value.length - 1)
        }
        attributes.set(key, value)
      }
    }
  }
  return attributes
}

export function isValidChallenge(attributes: Map<string, string>): boolean {
  let valid = false
  if (
    attributes.has('realm') &&
    attributes.has('service') &&
    attributes.has('scope')
  ) {
    valid = true
  }
  return valid
}

export class MapPrinter {
  entries: Map<string, string> = new Map<string, string>()
  maxLength = 1

  add(entry: string, defaultValue: string): void {
    if (entry.length > this.maxLength) {
      this.maxLength = entry.length
    }
    this.entries.set(entry, defaultValue)
  }

  print(): void {
    const column = this.maxLength + 10
    for (const [key, value] of this.entries) {
      const spacer = ''.padEnd(column - key.length, ' ')
      core.info(`${key}${spacer}${value}`)
    }
  }
}

export class CleanupTaskStatistics {
  // action stats
  name: string
  numberMultiImagesDeleted: number
  numberImagesDeleted: number

  constructor(
    name: string,
    numberMultiImagesDeleted: number,
    numberImagesDeleted: number
  ) {
    this.name = name
    this.numberMultiImagesDeleted = numberMultiImagesDeleted
    this.numberImagesDeleted = numberImagesDeleted
  }

  add(other: CleanupTaskStatistics): CleanupTaskStatistics {
    return new CleanupTaskStatistics(
      this.name,
      this.numberMultiImagesDeleted + other.numberMultiImagesDeleted,
      this.numberImagesDeleted + other.numberImagesDeleted
    )
  }

  print(): void {
    core.startGroup(`[${this.name}] Cleanup statistics`)
    // print action statistics
    if (this.numberMultiImagesDeleted > 0) {
      core.info(
        `multi architecture images deleted = ${this.numberMultiImagesDeleted}`
      )
    }
    core.info(`total images deleted = ${this.numberImagesDeleted}`)
    core.endGroup()
  }
}

import { describe, it, expect, beforeEach, vi } from 'vitest'
import * as core from '@actions/core'
import { ManifestAnalyzer } from '../manifest-analyzer'
import { CleanupContext } from '../cleanup-types'
import { Config, LogLevel } from '../config'

vi.mock('@actions/core')

describe('ManifestAnalyzer', () => {
  let analyzer: ManifestAnalyzer
  let context: CleanupContext
  let mockPackageRepo: any
  let mockRegistry: any
  let config: Config

  beforeEach(() => {
    vi.clearAllMocks()

    mockPackageRepo = {
      getDigests: vi.fn().mockReturnValue(new Set()),
      getTags: vi.fn().mockReturnValue(new Set()),
      getDigestByTag: vi.fn(),
      getPackageByDigest: vi.fn(),
      getIdByDigest: vi.fn()
    }

    mockRegistry = {
      getManifestByDigest: vi.fn(),
      getManifestByTag: vi.fn()
    }

    config = new Config()
    config.logLevel = LogLevel.INFO

    context = {
      config,
      registry: mockRegistry,
      packageRepo: mockPackageRepo,
      targetPackage: 'test-package'
    }

    analyzer = new ManifestAnalyzer(context)
  })

  describe('loadDigestUsedByMap', () => {
    it('returns an empty map for a single-arch image with no children', async () => {
      mockPackageRepo.getDigests.mockReturnValue(new Set(['sha256:single']))
      mockRegistry.getManifestByDigest.mockResolvedValue({
        layers: [{ digest: 'sha256:layer1' }]
      })

      const map = await analyzer.loadDigestUsedByMap()

      expect(map.size).toBe(0)
    })

    it('maps each child digest to its multi-arch parent', async () => {
      const parent = 'sha256:parent'
      const childAmd = 'sha256:amd64'
      const childArm = 'sha256:arm64'
      mockPackageRepo.getDigests.mockReturnValue(
        new Set([parent, childAmd, childArm])
      )
      mockRegistry.getManifestByDigest.mockImplementation(
        async (digest: string) => {
          if (digest === parent) {
            return {
              manifests: [{ digest: childAmd }, { digest: childArm }]
            }
          }
          return { layers: [] }
        }
      )

      const map = await analyzer.loadDigestUsedByMap()

      expect(map.get(childAmd)).toEqual(new Set([parent]))
      expect(map.get(childArm)).toEqual(new Set([parent]))
    })

    it('records all parents when a child is shared between two indexes', async () => {
      // Regression for FINDINGS.md #19: previously the code removed the
      // child from the iteration set on first encounter, so the second
      // parent never registered itself — causing cascade-delete to wrongly
      // treat shared children as single-parent.
      const parentA = 'sha256:parentA'
      const parentB = 'sha256:parentB'
      const sharedChild = 'sha256:shared'
      mockPackageRepo.getDigests.mockReturnValue(
        new Set([parentA, parentB, sharedChild])
      )
      mockRegistry.getManifestByDigest.mockImplementation(
        async (digest: string) => {
          if (digest === parentA || digest === parentB) {
            return { manifests: [{ digest: sharedChild }] }
          }
          return { layers: [] }
        }
      )

      const map = await analyzer.loadDigestUsedByMap()

      expect(map.get(sharedChild)).toEqual(new Set([parentA, parentB]))
    })

    it('records all parents regardless of iteration order', async () => {
      // Same scenario as above but parents inserted in reverse order.
      const parentA = 'sha256:parentA'
      const parentB = 'sha256:parentB'
      const sharedChild = 'sha256:shared'
      mockPackageRepo.getDigests.mockReturnValue(
        new Set([parentB, parentA, sharedChild])
      )
      mockRegistry.getManifestByDigest.mockImplementation(
        async (digest: string) => {
          if (digest === parentA || digest === parentB) {
            return { manifests: [{ digest: sharedChild }] }
          }
          return { layers: [] }
        }
      )

      const map = await analyzer.loadDigestUsedByMap()

      expect(map.get(sharedChild)).toEqual(new Set([parentA, parentB]))
    })

    it('records all parents when three indexes share the same child', async () => {
      const parentA = 'sha256:parentA'
      const parentB = 'sha256:parentB'
      const parentC = 'sha256:parentC'
      const sharedChild = 'sha256:shared'
      mockPackageRepo.getDigests.mockReturnValue(
        new Set([parentA, parentB, parentC, sharedChild])
      )
      mockRegistry.getManifestByDigest.mockImplementation(
        async (digest: string) => {
          if (digest === parentA || digest === parentB || digest === parentC) {
            return { manifests: [{ digest: sharedChild }] }
          }
          return { layers: [] }
        }
      )

      const map = await analyzer.loadDigestUsedByMap()

      expect(map.get(sharedChild)).toEqual(new Set([parentA, parentB, parentC]))
    })

    it('handles overlapping child sets (one shared child, one dedicated child each)', async () => {
      // image1 = [shared, onlyA]; image2 = [shared, onlyB]
      const parentA = 'sha256:parentA'
      const parentB = 'sha256:parentB'
      const shared = 'sha256:shared'
      const onlyA = 'sha256:onlyA'
      const onlyB = 'sha256:onlyB'
      mockPackageRepo.getDigests.mockReturnValue(
        new Set([parentA, parentB, shared, onlyA, onlyB])
      )
      mockRegistry.getManifestByDigest.mockImplementation(
        async (digest: string) => {
          if (digest === parentA) {
            return { manifests: [{ digest: shared }, { digest: onlyA }] }
          }
          if (digest === parentB) {
            return { manifests: [{ digest: shared }, { digest: onlyB }] }
          }
          return { layers: [] }
        }
      )

      const map = await analyzer.loadDigestUsedByMap()

      expect(map.get(shared)).toEqual(new Set([parentA, parentB]))
      expect(map.get(onlyA)).toEqual(new Set([parentA]))
      expect(map.get(onlyB)).toEqual(new Set([parentB]))
    })

    it('skips child manifests that are not present in the package list', async () => {
      // A manifest that references a child not in the repo should not be added.
      const parent = 'sha256:parent'
      mockPackageRepo.getDigests.mockReturnValue(new Set([parent]))
      mockRegistry.getManifestByDigest.mockResolvedValue({
        manifests: [{ digest: 'sha256:missing-child' }]
      })

      const map = await analyzer.loadDigestUsedByMap()

      expect(map.size).toBe(0)
    })
  })

  describe('initFilterSet', () => {
    it('removes child platform digests from the filter set', async () => {
      const parent = 'sha256:parent'
      const child = 'sha256:child'
      mockPackageRepo.getDigests.mockReturnValue(new Set([parent, child]))
      mockPackageRepo.getTags.mockReturnValue(new Set())
      mockRegistry.getManifestByDigest.mockImplementation(
        async (digest: string) => {
          if (digest === parent) {
            return { manifests: [{ digest: child }] }
          }
          return { layers: [] }
        }
      )

      const filterSet = await analyzer.initFilterSet()

      expect(filterSet.has(parent)).toBe(true)
      expect(filterSet.has(child)).toBe(false)
    })

    it('removes referrer-tagged digests (e.g. .sig) and their children', async () => {
      const parent = `sha256:${'a'.repeat(64)}`
      const referrerDigest = 'sha256:referrer'
      const referrerChild = 'sha256:refChild'
      const referrerTag = `sha256-${'a'.repeat(64)}.sig`

      mockPackageRepo.getDigests.mockReturnValue(
        new Set([parent, referrerDigest, referrerChild])
      )
      mockPackageRepo.getTags.mockReturnValue(new Set([referrerTag]))
      mockPackageRepo.getDigestByTag.mockImplementation((tag: string) =>
        tag === referrerTag ? referrerDigest : undefined
      )
      mockRegistry.getManifestByDigest.mockResolvedValue({ layers: [] })
      mockRegistry.getManifestByTag.mockResolvedValue({
        manifests: [{ digest: referrerChild }]
      })

      const filterSet = await analyzer.initFilterSet()

      expect(filterSet.has(parent)).toBe(true)
      expect(filterSet.has(referrerDigest)).toBe(false)
      expect(filterSet.has(referrerChild)).toBe(false)
    })
  })

  describe('buildLabel', () => {
    it('labels a platform manifest with architecture', async () => {
      const label = await analyzer.buildLabel({
        platform: { architecture: 'amd64' }
      })
      expect(label).toBe('architecture: amd64')
    })

    it('includes the variant when present', async () => {
      const label = await analyzer.buildLabel({
        platform: { architecture: 'arm', variant: 'v7' }
      })
      expect(label).toBe('architecture: arm/v7')
    })

    it('detects a buildx attestation by its in-toto layer media type', async () => {
      mockRegistry.getManifestByDigest.mockResolvedValue({
        layers: [{ mediaType: 'application/vnd.in-toto+json' }]
      })

      const label = await analyzer.buildLabel({
        digest: 'sha256:att',
        platform: { architecture: 'unknown' }
      })

      expect(label).toBe('application/vnd.in-toto+json')
    })

    it('labels sigstore attestations by artifactType prefix', async () => {
      const label = await analyzer.buildLabel({
        artifactType: 'application/vnd.dev.sigstore.bundle.v0.3+json'
      })
      expect(label).toBe('sigstore attestation')
    })

    it('falls back to the raw artifactType when not a sigstore bundle', async () => {
      const label = await analyzer.buildLabel({
        artifactType: 'application/vnd.cncf.notary.signature'
      })
      expect(label).toBe('application/vnd.cncf.notary.signature')
    })

    it('returns an empty label when there is no platform or artifactType', async () => {
      expect(await analyzer.buildLabel({})).toBe('')
    })
  })

  describe('primeManifests', () => {
    it('preloads child manifests by calling buildLabel on each known child', async () => {
      const parent = 'sha256:parent'
      const child = 'sha256:child'
      mockPackageRepo.getDigests.mockReturnValue(new Set([parent, child]))
      mockPackageRepo.getTags.mockReturnValue(new Set())
      mockRegistry.getManifestByDigest.mockImplementation(
        async (digest: string) => {
          if (digest === parent) {
            return {
              manifests: [
                { digest: child, platform: { architecture: 'amd64' } }
              ]
            }
          }
          return { layers: [] }
        }
      )

      await analyzer.primeManifests(new Set([parent]))

      // Parent fetched once via primeManifests itself. Child platform manifest
      // doesn't need fetching for an amd64 label, so we only verify the parent
      // was loaded.
      expect(mockRegistry.getManifestByDigest).toHaveBeenCalledWith(parent)
    })
  })

  describe('logging', () => {
    it('opens a "Loading manifests" group named for the target package', async () => {
      mockPackageRepo.getDigests.mockReturnValue(new Set(['sha256:x']))
      mockRegistry.getManifestByDigest.mockResolvedValue({ layers: [] })

      await analyzer.loadDigestUsedByMap()

      expect(core.startGroup).toHaveBeenCalledWith(
        '[test-package] Loading manifests'
      )
      expect(core.endGroup).toHaveBeenCalled()
    })
  })
})

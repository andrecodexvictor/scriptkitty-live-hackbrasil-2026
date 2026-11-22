/**
 * @file packages/runtime-guardian/tests/scope.test.mts
 * @description Comprehensive Test Suite for Resource Scope & Path Boundary Guard:
 * Directory Traversal, Root Containment, Null Byte Attacks, Encoding Bypasses,
 * NTFS ADS, UNC Paths, URI Schemes, and Sensitive Resource Blacklists.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import * as os from 'node:os';
import * as fsPromises from 'node:fs/promises';
import {
  validateAndResolvePath,
  ScopeBoundaryGuard,
  GuardianSecurityError,
  type ScopeGuardPolicy,
} from '../dist/index.js';

describe('Suite 1: Path Traversal & Root Containment', () => {
  let workspaceDir: string;
  let policy: ScopeGuardPolicy;

  beforeEach(async () => {
    workspaceDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'scope-test-'));
    policy = {
      enabled: true,
      allowedRoots: [workspaceDir],
      allowSensitiveFiles: false,
    };
  });

  afterEach(async () => {
    try {
      await fsPromises.rm(workspaceDir, { recursive: true, force: true });
    } catch {}
  });

  it('TEST_SCOPE_1: allows legitimate paths resolving inside allowed root', () => {
    const validRelative = 'src/components/button.tsx';
    const resolved = validateAndResolvePath(validRelative, policy);
    assert.equal(resolved, path.resolve(workspaceDir, validRelative));
  });

  it('TEST_SCOPE_2: blocks relative path traversal escaping root (../)', () => {
    const traversal = '../../../etc/passwd';
    assert.throws(
      () => validateAndResolvePath(traversal, policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_PATH_OUT_OF_BOUNDS');
        return true;
      }
    );
  });

  it('TEST_SCOPE_3: blocks absolute paths pointing outside allowed roots', () => {
    const outside = os.platform() === 'win32' ? 'C:\\Windows\\System32\\drivers\\etc\\hosts' : '/etc/shadow';
    assert.throws(
      () => validateAndResolvePath(outside, policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_PATH_OUT_OF_BOUNDS');
        return true;
      }
    );
  });

  it('TEST_SCOPE_4: blocks sibling directory boundary escape (/app-data vs /app)', () => {
    // Sibling directory with shared prefix must not be allowed
    const sibling = `${workspaceDir}-sibling/secret.txt`;
    assert.throws(
      () => validateAndResolvePath(sibling, policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_PATH_OUT_OF_BOUNDS');
        return true;
      }
    );
  });
});

describe('Suite 2: Null Byte & Control Character Defense', () => {
  const policy: ScopeGuardPolicy = {
    enabled: true,
    allowedRoots: [process.cwd()],
  };

  it('TEST_NULL_1: blocks literal null bytes in path', () => {
    assert.throws(
      () => validateAndResolvePath('safe_file.txt\0/../../etc/passwd', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_PATH_NULL_BYTE');
        return true;
      }
    );
  });

  it('TEST_NULL_2: blocks URL-encoded null bytes (%00)', () => {
    assert.throws(
      () => validateAndResolvePath('index.js%00.png', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_PATH_NULL_BYTE');
        return true;
      }
    );
  });

  it('TEST_NULL_3: blocks ASCII control characters in path', () => {
    assert.throws(
      () => validateAndResolvePath('path/with/\x07bell', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_PATH_NULL_BYTE');
        return true;
      }
    );
  });
});

describe('Suite 3: Encoding & Unicode Normalization Traversal', () => {
  const policy: ScopeGuardPolicy = {
    enabled: true,
    allowedRoots: [process.cwd()],
  };

  it('TEST_ENC_1: blocks double URL encoded traversal (%252e%252e%252f)', () => {
    assert.throws(
      () => validateAndResolvePath('%252e%252e%252fetc%252fpasswd', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_PATH_DOUBLE_ENCODING');
        return true;
      }
    );
  });

  it('TEST_ENC_2: normalizes fullwidth Unicode dot traversal (\\uff0e\\uff0e\\uff0f)', () => {
    // \uff0e\uff0e\uff0f normalizes to ../
    assert.throws(
      () => validateAndResolvePath('\uff0e\uff0e\uff0f\uff0e\uff0e\uff0fetc/passwd', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_PATH_OUT_OF_BOUNDS');
        return true;
      }
    );
  });
});

describe('Suite 4: Windows Namespace & UNC Traversal', () => {
  const policy: ScopeGuardPolicy = {
    enabled: true,
    allowedRoots: [process.cwd()],
  };

  it('TEST_WIN_1: blocks UNC network paths (\\\\attacker\\share)', () => {
    assert.throws(
      () => validateAndResolvePath('\\\\attacker-smb.evil.com\\share\\file.txt', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_PATH_UNC_FORBIDDEN');
        return true;
      }
    );
  });

  it('TEST_WIN_2: blocks NTFS Alternate Data Streams (::$DATA)', () => {
    assert.throws(
      () => validateAndResolvePath('document.txt::$DATA', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_PATH_NTFS_ADS');
        return true;
      }
    );
  });

  it('TEST_WIN_3: blocks named NTFS streams (file:hidden)', () => {
    assert.throws(
      () => validateAndResolvePath('notes.txt:hidden_stream', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_PATH_NTFS_ADS');
        return true;
      }
    );
  });
});

describe('Suite 5: Resource URI Schemes', () => {
  const policy: ScopeGuardPolicy = {
    enabled: true,
    allowedRoots: [process.cwd()],
    allowedUriSchemes: ['file', 'sqlite'],
  };

  it('TEST_URI_1: allows permitted file:// URI resolving within root', () => {
    const cwdUrl = new URL(`file://${process.cwd().replace(/\\/g, '/')}/package.json`).href;
    const resolved = validateAndResolvePath(cwdUrl, policy);
    assert.ok(resolved.endsWith('package.json'));
  });

  it('TEST_URI_2: blocks prohibited URI schemes (gopher://, http://)', () => {
    assert.throws(
      () => validateAndResolvePath('gopher://internal.server/data', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_INVALID_URI_SCHEME');
        return true;
      }
    );

    assert.throws(
      () => validateAndResolvePath('http://attacker.com/payload.sh', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_INVALID_URI_SCHEME');
        return true;
      }
    );
  });
});

describe('Suite 6: Sensitive File & Directory Blacklist', () => {
  let workspaceDir: string;
  let policy: ScopeGuardPolicy;

  beforeEach(async () => {
    workspaceDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'scope-blacklist-'));
    policy = {
      enabled: true,
      allowedRoots: [workspaceDir],
      allowSensitiveFiles: false,
    };
  });

  afterEach(async () => {
    try {
      await fsPromises.rm(workspaceDir, { recursive: true, force: true });
    } catch {}
  });

  it('TEST_BLACK_1: blocks access to .git and .git/config', () => {
    assert.throws(
      () => validateAndResolvePath('.git/config', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_SENSITIVE_RESOURCE_BLOCKED');
        return true;
      }
    );
  });

  it('TEST_BLACK_2: blocks access to .env and environment variants', () => {
    assert.throws(
      () => validateAndResolvePath('.env', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_SENSITIVE_RESOURCE_BLOCKED');
        return true;
      }
    );

    assert.throws(
      () => validateAndResolvePath('.env.production', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_SENSITIVE_RESOURCE_BLOCKED');
        return true;
      }
    );
  });

  it('TEST_BLACK_3: blocks access to SSH private keys (id_rsa, id_ed25519)', () => {
    assert.throws(
      () => validateAndResolvePath('id_rsa', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_SENSITIVE_RESOURCE_BLOCKED');
        return true;
      }
    );

    assert.throws(
      () => validateAndResolvePath('keys/id_ed25519', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_SENSITIVE_RESOURCE_BLOCKED');
        return true;
      }
    );
  });

  it('TEST_BLACK_4: blocks access to certificates and private key files (*.pem, *.key)', () => {
    assert.throws(
      () => validateAndResolvePath('certs/server.pem', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_SENSITIVE_RESOURCE_BLOCKED');
        return true;
      }
    );

    assert.throws(
      () => validateAndResolvePath('ssl/private.key', policy),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_SENSITIVE_RESOURCE_BLOCKED');
        return true;
      }
    );
  });

  it('TEST_BLACK_5: allows sensitive files when explicitly permitted by policy', () => {
    const permissivePolicy: ScopeGuardPolicy = {
      ...policy,
      allowSensitiveFiles: true,
    };
    const resolved = validateAndResolvePath('.env', permissivePolicy);
    assert.equal(resolved, path.resolve(workspaceDir, '.env'));
  });
});

describe('Suite 7: ScopeBoundaryGuard Class Integration', () => {
  it('TEST_INSPECT_1: inspects tool arguments and blocks traversal paths', () => {
    const guard = new ScopeBoundaryGuard({
      enabled: true,
      allowedRoots: [process.cwd()],
    });

    const maliciousArgs = {
      target: 'api',
      path: '../../../../etc/shadow',
    };

    const decision = guard.inspect(maliciousArgs);
    assert.equal(decision.verdict, 'BLOCK');
    assert.equal(decision.detector, 'scope_guard');
    assert.equal(decision.rule_id, 'E_PATH_OUT_OF_BOUNDS');
  });

  it('TEST_INSPECT_2: allows legitimate arguments within allowed scope', () => {
    const guard = new ScopeBoundaryGuard({
      enabled: true,
      allowedRoots: [process.cwd()],
    });

    const benignArgs = {
      path: 'src/index.ts',
      options: { recursive: false },
    };

    const decision = guard.inspect(benignArgs);
    assert.equal(decision.verdict, 'ALLOW');
    assert.equal(decision.rule_id, 'scope_verified');
  });
});

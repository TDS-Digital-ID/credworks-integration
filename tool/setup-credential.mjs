import { lstatSync, readFileSync } from 'node:fs';

export function credentialInput(state) {
  return state.binding.credential ?? {
    definition: {
      id: state.binding.runtimeOrigin + '/definitions/club-membership', version: '1',
      credential_type: 'SyntheticClubMembership', label: 'Synthetic club membership', max_validity_seconds: 3600,
      claims: [
        { name: 'member', label: 'Member', value_type: 'boolean', required: true },
        { name: 'club', label: 'Club', value_type: 'string', required: true },
      ],
      profiles: [{ name: 'membership', claim_paths: [['credentialSubject', 'member']] }],
    },
    claims: { member: true, club: 'Example Robotics Club' },
  };
}

export async function readCredential(path, runtimeOrigin) {
  try {
    const info = lstatSync(path);
    if (!info.isFile() || info.size > 16384) throw Error();
    const input = JSON.parse(readFileSync(path, 'utf8'));
    if (!input || Object.keys(input).sort().join() !== 'claims,definition') throw Error();
    const { definition, claims } = input;
    const id = new URL(definition.id);
    if (id.origin !== runtimeOrigin || id.username || id.password || id.search || id.hash ||
        !id.pathname.startsWith('/definitions/') || definition.profiles?.length !== 1) throw Error();
    const core = await import('@unsw-vc/identity-core-node');
    core.validateScalarDefinition(definition);
    core.validateScalarSubject({ definition, subject: claims, mode: 'complete' });
    // The guided check uses one scalar profile; structured definitions retain their existing advanced workflow.
    if (definition.claims.some(claim => ['object', 'array'].includes(claim.value_type) || (claim.path && (claim.path.length !== 2 || claim.path[1] !== claim.name)))) throw Error();
    return input;
  } catch { throw Error('SETUP_DEFINITION_REFUSED'); }
}

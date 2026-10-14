/**
 * Multidex member selection inside an APK/ZIP. Android auto-loads the root
 * members `classes.dex`, `classes2.dex`, `classes3.dex`, … (no directory); a
 * caller may still select any other `.dex` member explicitly by its exact path.
 */

const ROOT_DEX = /^classes([0-9]*)\.dex$/;

/** A root, auto-loaded `classes*.dex` member (not one nested under a directory). */
export const isRootDexMember = (path: string): boolean => ROOT_DEX.test(path);

/**
 * Load order of a root dex member: `classes.dex` is 1, `classesN.dex` is N.
 * Non-root members sort last so an explicit selection stays stable.
 */
export const dexMemberOrder = (path: string): number => {
  const match = ROOT_DEX.exec(path);
  if (match === null) return Number.MAX_SAFE_INTEGER;
  return match[1] === "" ? 1 : Number(match[1]);
};

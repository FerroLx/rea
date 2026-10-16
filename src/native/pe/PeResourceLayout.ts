import { peFailure, readPeImageLayout } from "./PeImageLayout.js";

export { peFailure, requirePeRange } from "./PeImageLayout.js";

/**
 * The resource directory (data directory 2) of a PE image, with RVA mapping
 * delegated to the shared {@link readPeImageLayout} owner.
 */
export const readPeResourceLayout = (bytes: Buffer) => {
  const layout = readPeImageLayout(bytes);
  const directory = layout.dataDirectory(2);
  const rva = directory?.rva ?? 0;
  const size = directory?.size ?? 0;
  if ((rva === 0) !== (size === 0))
    peFailure("Inconsistent PE resource directory RVA/size.");
  return {
    format: layout.format,
    machine: layout.machine,
    directoryAt: layout.directoriesAt + 16,
    rva,
    size,
    map: (target: number, length: number): number =>
      layout.map(target, length, "Resource"),
  };
};

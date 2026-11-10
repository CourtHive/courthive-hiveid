// Barrel for storage interfaces — mirrors competition-factory-server so ported
// account code that imports `from 'src/storage/interfaces'` resolves unchanged.
// Re-exports both the DI token constants and their interface types.

export * from './user-storage.interface';
export * from './user-provider-storage.interface';
export * from './user-provisioner-storage.interface';
export * from './provisioner-provider-storage.interface';
export * from './provider-storage.interface';
export * from './refresh-token-storage.interface';
export * from './auth-code-storage.interface';

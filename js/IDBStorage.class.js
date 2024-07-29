import { Common } from './Common.class.js'
/**
 * Store Callback
 * @typedef {function(IDBObjectStore)}
 * @callback IDBStorage.StoreCallback
 * @param {IDBObjectStore} store
 */

/**
 * IDBStorage Class
 * @class
 */
export class IDBStorage {
  /**
   * Creates an instance of IDBStorage, initializes IndexedDB and connects to the specified Database
   * @param {string} databaseName
   * @param {number} [databaseVersion=1]
   */
  constructor (databaseName, databaseVersion = 1) {
    this.idb = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB || window.shimIndexedDB
    this.db = (Common.isString(databaseName) ? databaseName : null)
    this.dbV = (isNaN(databaseVersion) || databaseVersion < 1 ? 1 : databaseVersion)
  }

  get IndexedDB () {
    return (this.idb instanceof window.IDBFactory ? this.idb : false)
  }

  get OpenDB () {
    return (this.open instanceof window.IDBOpenDBRequest ? this.open : false)
  }

  /**
   * Call on Store
   * @param {string} objectStoreName
   * @param {IDBStorage.StoreCallback} storeCallback
   * @param {string} [storeKeyPath='id']
   * @memberof IDBStorage
   */
  call (objectStoreName, storeCallback, storeKeyPath = 'id') {
    if (this.IndexedDB !== false) {
      const open = this.IndexedDB.open(this.db, this.dbV)

      if (open instanceof window.IDBOpenDBRequest && storeCallback instanceof Function) {
        open.onupgradeneeded = () => {
          return open.result.createObjectStore(objectStoreName, { keyPath: storeKeyPath })
        }

        open.onsuccess = () => {
          const db = open.result
          const tx = db.transaction(objectStoreName, 'readwrite')
          const store = tx.objectStore(objectStoreName)

          storeCallback(store)

          tx.oncomplete = () => {
            db.close()
          }
        }
      } else return false
    } else return false
  }
}

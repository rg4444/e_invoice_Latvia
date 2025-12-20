# VDAA Java SDK – UnifiedServiceInterface call sequence map

Source: `examples/VDAA_docs/Client/JAVA/VraaDivClient.jar`

## Service methods (UnifiedServiceInterface)

### Synchronous operations
- `sendMessage`
- `initSendMessage`
- `sendAttachmentSection`
- `completeSendMessage`
- `getMessageServerConfirmation`
- `confirmMessage`
- `getMessageList`
- `getMessage`
- `getAttachmentSection`
- `getNotificationList`
- `confirmNotificationList`
- `createAddresseeUnit`
- `deleteAddresseeUnit`
- `updateAddresseeUnit`
- `searchAddresseeUnit`
- `getAddresseeUnit`
- `getPublicKeyList`
- `validateEAddress`
- `activateNaturalPersonAccount`
- `activateLegalPersonAccount`
- `deactivateNaturalPerson`
- `deactivateLegalPerson`
- `deanullAddressee`
- `getActiveBulkReferenceNumber`
- `getInitialAddresseeRecordList`
- `getChangedAddresseeRecordList`
- `getResultJournal`
- `createInstitution`

### Async-pattern operations
These follow a `Start` → `Result` → `Confirm` sequence in naming.

- `getChangedAddresseeRecordListAsyncStart`
- `getChangedAddresseeRecordListAsyncResult`
- `getChangedAddresseeRecordListAsyncConfirm`
- `addresseeOwnerUpdateAsyncStart`
- `addresseeStatusUpdateAsyncStart`
- `addresseeStatusUpdateAsyncUnlock`
- `validateAddresseesAsyncStart`
- `validateAddresseesAsyncResult`
- `validateAddresseesAsyncConfirm`
- `getAccountStatusHistoryAsyncStart`
- `getAccountStatusHistoryAsyncResult`
- `getAccountStatusHistoryAsyncConfirm`

## Naming cues for sequencing
- Methods prefixed with `init` or `complete` suggest multi-step workflows (e.g., `initSendMessage` → `sendAttachmentSection` → `completeSendMessage`).
- Methods containing `AsyncStart`, `AsyncResult`, `AsyncConfirm`, or `AsyncUnlock` indicate asynchronous flows or follow-up confirmation steps.

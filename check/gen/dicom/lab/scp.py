# pynetdicom 2.1.1 Query/Retrieve SCP for the DICOM check captures (AE LABPACS):
# C-ECHO, C-STORE (in memory), C-FIND with wildcard matching and C-CANCEL, C-MOVE to LABSCU.
import fnmatch, sys, logging, time
from pydicom.dataset import Dataset
from pynetdicom import AE, evt, AllStoragePresentationContexts, ALL_TRANSFER_SYNTAXES
from pynetdicom.sop_class import (Verification, PatientRootQueryRetrieveInformationModelFind,
    PatientRootQueryRetrieveInformationModelMove, StudyRootQueryRetrieveInformationModelFind,
    StudyRootQueryRetrieveInformationModelMove)
STORE = []
def h_store(event):
    ds = event.dataset; ds.file_meta = event.file_meta; STORE.append(ds); return 0x0000
def match(q, ds):
    pn = str(q.get('PatientName', '') or '')
    if pn and not fnmatch.fnmatchcase(str(ds.PatientName), pn): return False
    suid = q.get('StudyInstanceUID', '')
    if suid and ds.StudyInstanceUID != suid: return False
    return True
def h_find(event):
    q = event.identifier
    for ds in STORE:
        if event.is_cancelled:
            yield (0xFE00, None); return
        if match(q, ds):
            time.sleep(0.15)
            if event.is_cancelled:
                yield (0xFE00, None); return
            r = Dataset(); r.QueryRetrieveLevel = q.QueryRetrieveLevel
            r.PatientName = ds.PatientName; r.PatientID = ds.PatientID
            if 'StudyInstanceUID' in q: r.StudyInstanceUID = ds.StudyInstanceUID
            yield (0xFF00, r)
def h_move(event):
    if event.move_destination.strip() != b'LABSCU' and event.move_destination.strip() != 'LABSCU':
        yield (None, None); return
    yield ('10.77.0.20', 11113)
    m = [d for d in STORE if match(event.identifier, d)]
    yield len(m)
    for d in m: yield (0xFF00, d)
ae = AE(ae_title='LABPACS')
ae.supported_contexts = AllStoragePresentationContexts
for c in (Verification, PatientRootQueryRetrieveInformationModelFind, PatientRootQueryRetrieveInformationModelMove,
          StudyRootQueryRetrieveInformationModelFind, StudyRootQueryRetrieveInformationModelMove):
    ae.add_supported_context(c, ALL_TRANSFER_SYNTAXES)
ae.add_requested_context('1.2.840.10008.5.1.4.1.1.2')
ae.start_server(('0.0.0.0', 11112), block=True, evt_handlers=[(evt.EVT_C_STORE, h_store), (evt.EVT_C_FIND, h_find), (evt.EVT_C_MOVE, h_move)])

# pynetdicom client: echo, store, 6 wildcard finds, a cancelled find, a move
import time, sys
from pydicom import dcmread
from pydicom.dataset import Dataset
from pynetdicom import AE, evt, StoragePresentationContexts, build_role
from pynetdicom.sop_class import (Verification, PatientRootQueryRetrieveInformationModelFind,
    StudyRootQueryRetrieveInformationModelMove, CTImageStorage)
H, P, CALLED = '10.77.0.10', 11112, 'LABPACS'
ae = AE(ae_title='LABSCU'); ae.add_requested_context(Verification)
a = ae.associate(H, P, ae_title=CALLED); a.send_c_echo(); a.release()
ae = AE(ae_title='LABSCU'); ae.requested_contexts = StoragePresentationContexts
a = ae.associate(H, P, ae_title=CALLED)
for i in (1, 2, 3): a.send_c_store(dcmread(f'/tmp/img{i}.dcm'))
a.release()
ae = AE(ae_title='LABSCU'); ae.add_requested_context(PatientRootQueryRetrieveInformationModelFind)
a = ae.associate(H, P, ae_title=CALLED)
for pn in ('D*', 'A*', 'S*', 'M*', 'J*', '*'):
    q = Dataset(); q.QueryRetrieveLevel = 'PATIENT'; q.PatientName = pn; q.PatientID = ''
    for st, ds in a.send_c_find(q, PatientRootQueryRetrieveInformationModelFind): pass
a.release()
a = ae.associate(H, P, ae_title=CALLED)
q = Dataset(); q.QueryRetrieveLevel = 'PATIENT'; q.PatientName = '*'; q.PatientID = ''
for st, ds in a.send_c_find(q, PatientRootQueryRetrieveInformationModelFind, msg_id=7):
    if st and st.Status == 0xFF00:
        a.send_c_cancel(7, None, PatientRootQueryRetrieveInformationModelFind); 
a.release()
ae = AE(ae_title='LABSCU'); ae.add_requested_context(StudyRootQueryRetrieveInformationModelMove)
ae.add_supported_context(CTImageStorage)
srv = ae.start_server(('0.0.0.0', 11113), block=False, evt_handlers=[(evt.EVT_C_STORE, lambda e: 0)])
a = ae.associate(H, P, ae_title=CALLED)
q = Dataset(); q.QueryRetrieveLevel = 'STUDY'; q.StudyInstanceUID = '1.2.826.0.1.3680043.2.1125.2.1'
for st, ds in a.send_c_move(q, 'LABSCU', StudyRootQueryRetrieveInformationModelMove): pass
a.release(); time.sleep(0.5); srv.shutdown()
ae = AE(ae_title='LABSCU'); ae.add_requested_context(Verification)
a = ae.associate(H, P, ae_title=CALLED); a.send_c_echo(); a.release()

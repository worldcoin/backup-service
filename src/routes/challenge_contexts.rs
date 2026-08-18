//! Maps each challenge request to the operation the challenge authorizes. Keeping every mapping
//! in one place makes it obvious that no two operations share a context.

use crate::challenge_manager::ChallengeContext;
use types::endpoints::{
    AddSyncFactorChallengeKeypairRequest, CreateChallengeKeypairRequest,
    DeleteBackupChallengeKeypairRequest, DeleteFactorChallengeKeypairRequest,
    ResetChallengeKeypairRequest, RetrieveChallengeKeypairRequest,
    RetrieveMetadataChallengeKeypairRequest, SyncChallengeKeypairRequest,
    VerifyFactorChallengeKeypairRequest,
};

impl From<CreateChallengeKeypairRequest> for ChallengeContext {
    fn from(_: CreateChallengeKeypairRequest) -> Self {
        ChallengeContext::Create {}
    }
}

impl From<RetrieveChallengeKeypairRequest> for ChallengeContext {
    fn from(_: RetrieveChallengeKeypairRequest) -> Self {
        ChallengeContext::Retrieve {}
    }
}

impl From<VerifyFactorChallengeKeypairRequest> for ChallengeContext {
    fn from(_: VerifyFactorChallengeKeypairRequest) -> Self {
        ChallengeContext::VerifyFactor {}
    }
}

impl From<AddSyncFactorChallengeKeypairRequest> for ChallengeContext {
    fn from(_: AddSyncFactorChallengeKeypairRequest) -> Self {
        ChallengeContext::AddSyncFactor {}
    }
}

impl From<SyncChallengeKeypairRequest> for ChallengeContext {
    fn from(_: SyncChallengeKeypairRequest) -> Self {
        ChallengeContext::Sync {}
    }
}

impl From<RetrieveMetadataChallengeKeypairRequest> for ChallengeContext {
    fn from(_: RetrieveMetadataChallengeKeypairRequest) -> Self {
        ChallengeContext::RetrieveMetadata {}
    }
}

impl From<DeleteFactorChallengeKeypairRequest> for ChallengeContext {
    fn from(request: DeleteFactorChallengeKeypairRequest) -> Self {
        ChallengeContext::DeleteFactor {
            factor_id: request.factor_id,
        }
    }
}

impl From<DeleteBackupChallengeKeypairRequest> for ChallengeContext {
    fn from(_: DeleteBackupChallengeKeypairRequest) -> Self {
        ChallengeContext::DeleteBackup {}
    }
}

impl From<ResetChallengeKeypairRequest> for ChallengeContext {
    fn from(request: ResetChallengeKeypairRequest) -> Self {
        ChallengeContext::Reset {
            backup_account_id: request.backup_account_id,
        }
    }
}

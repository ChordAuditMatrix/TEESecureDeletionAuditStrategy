/* SPDX-License-Identifier: GPL-3.0-or-later */
/** @file strategy.h @brief Native CoreLib implementation of the TEE deletion
 * protocol. */
#ifndef CAMATRIX_TEE_SECURE_DELETION_STRATEGY_H
#define CAMATRIX_TEE_SECURE_DELETION_STRATEGY_H

#include "ChordAuditMatrixLib/interfaces/audit/dynamic_strategy.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/request_result.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace CAMatrix::Audit::Strategies {

/**
 * Implements the complete deletion sequence in the patent rather than using
 * SM9Static's ordinary possession proof: TagGen -> Maintain(Delete) ->
 * ChallengeGen -> ProofGen -> ProofVerify.  In particular, proof verification
 * uses the deletion equation e(Omega,g2)=e(u^M,pk1)e(prod H2(w_i),pk2).
 */
class TEESecureDeletionAuditStrategy final
    : public CAMatrix::Audit::Core::DynamicAuditStrategy {
public:
  std::string algorithmType() const override { return "TEESecureDeletion"; }
  std::string version() const override { return "2.0.0"; }

  CAMatrix::Audit::Messages::Capabilities caps() const override;
  CAMatrix::Audit::Core::StateMaintenanceParty
  stateMaintenanceParty() const override;
  std::shared_ptr<CAMatrix::Audit::Core::DynamicPdpStateStore>
  createStateStore(CAMatrix::Audit::Core::BlockMetadataFactory metadataFactory)
      const override;
  void
  setAlgorithm(CAMatrix::Crypto::CryptoGeneralAlgorithmPtr algorithm) override;

  CAMatrix::Audit::Messages::InitializeAlgorithmResult initializeAlgorithm(
      const CAMatrix::Audit::Messages::InitializeAlgorithmRequest &input)
      override;
  CAMatrix::Audit::Messages::GenerateKeysResult generateKeys(
      const CAMatrix::Audit::Messages::GenerateKeysRequest &input) override;
  CAMatrix::Audit::Messages::GenerateTagsResult generateTags(
      const CAMatrix::Audit::Messages::GenerateTagsRequest &input) override;
  CAMatrix::Audit::Messages::MaintainResult
  maintenance(const CAMatrix::Audit::Messages::MaintainRequest &input) override;
  CAMatrix::Audit::Messages::GenerateChallengesResult generateChallenges(
      const CAMatrix::Audit::Messages::GenerateChallengesRequest &input)
      override;
  CAMatrix::Audit::Messages::GenerateProofsResult generateProofs(
      const CAMatrix::Audit::Messages::GenerateProofsRequest &input) override;
  CAMatrix::Audit::Messages::VerifyProofsResult verifyProofs(
      const CAMatrix::Audit::Messages::VerifyProofsRequest &input) override;
  CAMatrix::Audit::Messages::AuditRequestVariantPtr
  createRequest(CAMatrix::Audit::Core::AuditOperation operation,
                const CAMatrix::Audit::Core::AuditOperationContext &context,
                const CAMatrix::Audit::Messages::RawInput &input = {}) override;

  static std::vector<std::vector<std::uint8_t>>
  teeOverwrite(const std::vector<std::vector<std::uint8_t>> &blocks,
               const std::vector<std::size_t> &oneBasedIndices,
               const std::vector<std::uint8_t> &userKeyShare,
               const std::vector<std::uint8_t> &teeKeyShare,
               const std::string &fileId);

  /** In-place software model of the sealed TEE overwrite operation. */
  static void
  teeOverwriteInPlace(std::vector<std::vector<std::uint8_t>> &blocks,
                      const std::vector<std::size_t> &oneBasedIndices,
                      const std::vector<std::uint8_t> &userKeyShare,
                      const std::vector<std::uint8_t> &teeKeyShare,
                      const std::string &fileId);

  /** Stable software stand-in for a TEE deletion attestation binding. */
  static std::uint64_t
  attestationBinding(const std::string &fileId,
                     const std::vector<std::size_t> &oneBasedIndices,
                     const std::vector<std::uint8_t> &teeKeyShare);

protected:
  const CAMatrix::Audit::Core::AuditStrategyArtifactFactory &
  artifactFactory() const override;

private:
  CAMatrix::Crypto::CryptoGeneralAlgorithmPtr algorithm_;
};
} // namespace CAMatrix::Audit::Strategies

namespace CAMatrix::Audit::Core {
extern "C" AuditStrategy *create_audit_strategy() noexcept;
extern "C" void destroy_audit_strategy(AuditStrategy *strategy) noexcept;
} // namespace CAMatrix::Audit::Core
#endif

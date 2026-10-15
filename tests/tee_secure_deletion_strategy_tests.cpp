/* SPDX-License-Identifier: GPL-3.0-or-later */
/** @file tee_secure_deletion_strategy_tests.cpp
 *  @brief CoreLib lifecycle smoke test for TEE secure deletion. */

#include "TEESecureDeletionAuditStrategy/strategy.h"

#include "TEESecureDeletionAuditStrategy/deletion_state_store.h"

#include "ChordAuditMatrixLib/implementations/audit/state_stores/in_memory_block_metadata_collection.h"
#include "ChordAuditMatrixLib/implementations/audit/data/memory_audit_block_source.h"
#include "ChordAuditMatrixLib/interfaces/audit/engine.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/audit_data_map.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/raw_input.h"
#include "ChordAuditMatrixLib/interfaces/audit/operation_context.h"
#include "ChordAuditMatrixLib/interfaces/audit/state_stores/dynamic_pdp_state_store.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <json/json.h>

namespace {
using CAMatrix::Audit::Core::AuditEngineFactory;
using CAMatrix::Audit::Core::AuditOperationContext;
using CAMatrix::Audit::Data::AuditBlockSourcePtr;
using CAMatrix::Audit::Data::MemoryAuditBlockSource;
using CAMatrix::Audit::Messages::AuditDataMap;
using CAMatrix::Audit::Messages::RawInput;
using CAMatrix::Audit::Messages::TagsPtr;
using CAMatrix::Audit::Messages::MaintenanceOpType;

RawInput jsonInput(const Json::Value &value) {
  return RawInput(std::make_shared<std::string>(Json::FastWriter().write(value)));
}

bool verify(CAMatrix::Audit::Core::AuditEngine &engine,
            AuditOperationContext &context, bool replay) {
  auto proofInput = std::make_shared<AuditDataMap>();
  proofInput->emplace("adversarialReplay", replay);
  engine.generateProofs(RawInput(proofInput), context);
  if (!context.generateProofsResult || !context.generateProofsResult->proves)
    return false;

  Json::Value verifyInput;
  verifyInput["fileId"] = "tee-test-file";
  verifyInput["userId"] = "tee-test-user";
  engine.verifyProofs(jsonInput(verifyInput), context);
  return context.verifyProofsResult && context.verifyProofsResult->ok;
}

int fail(const char *message) {
  std::cerr << "TEE StateStore regression: " << message << '\n';
  return EXIT_FAILURE;
}
} // namespace

int main() {
  using Strategy = CAMatrix::Audit::Strategies::TEESecureDeletionAuditStrategy;
  try {
    // Exercise CoreLib's per-operation state store contract and TEE protocol
    // state ownership.
    auto engine = AuditEngineFactory::createInstance();
    auto strategy = std::make_shared<Strategy>();
    auto stateStore = engine->createStateStore(strategy);
    if (!stateStore)
      return fail("strategy did not create a StateStore");
    const std::string stateFileId = "tee-store-contract-file";
    stateStore->addFile(stateFileId);
    bool duplicateFileRejected = false;
    try {
      stateStore->addFile(stateFileId);
    } catch (const std::runtime_error &) {
      duplicateFileRejected = true;
    }
    if (!duplicateFileRejected)
      return fail("duplicate file was accepted");
    const auto collection = stateStore->getBlockMetadataCollection(stateFileId);
    bool missingFileRejected = false;
    try {
      stateStore->setBlockMetadataCollection("missing-tee-file", collection);
    } catch (const std::runtime_error &) {
      missingFileRejected = true;
    }
    if (!missingFileRejected)
      return fail("metadata collection injection accepted an unknown file");
    AuditOperationContext context;
    context.strategy = strategy;
    context.stateStore = stateStore;

    engine->initializeAlgorithm(RawInput{}, context);
    engine->generateKeys(RawInput{}, context);

    auto blocks = std::make_shared<MemoryAuditBlockSource>(
        std::vector<std::vector<std::uint8_t>>{{1, 2, 3, 4}, {5, 6, 7, 8},
                                                {9, 10, 11, 12}, {13, 14, 15, 16}},
        4, 0);
    auto tagInput = std::make_shared<AuditDataMap>();
    tagInput->emplace("blocks", AuditBlockSourcePtr(blocks));
    tagInput->emplace("fileId", std::string("tee-test-file"));
    tagInput->emplace("userId", std::string("tee-test-user"));
    engine->generateTags(RawInput(tagInput), context);
    if (!context.generateTagsResult || !context.generateTagsResult->tags)
      return fail("TagGen failed");
    const auto taggedFileState =
        std::dynamic_pointer_cast<
            CAMatrix::Audit::Strategies::TEEDeletion::DeletionFileState>(
            stateStore->getFileState("tee-test-file"));
    if (!taggedFileState || taggedFileState->values.size() != 4 ||
        taggedFileState->tags.size() != 4)
      return fail("TagGen did not persist TEE FileState through StateStore");

    // Secure deletion is intentionally transported through the normal dynamic
    // Update operation, without a Bench- or CoreLib-specific API.
    Json::Value updateInput;
    updateInput["fileId"] = "tee-test-file";
    updateInput["opType"] = static_cast<unsigned>(MaintenanceOpType::Update);
    updateInput["deletionMode"] = true;
    updateInput["seed"] = "tee-test-seed";
    updateInput["targetBlockIndices"] = Json::Value(Json::arrayValue);
    updateInput["targetBlockIndices"].append(2);
    engine->maintain(jsonInput(updateInput), context);
    if (!context.maintainResult)
      return fail("Maintenance produced no result");
    if (!context.maintainResult->tags)
      return fail("Maintenance returned no tags");
    const auto maintainedFileState =
        std::dynamic_pointer_cast<
            CAMatrix::Audit::Strategies::TEEDeletion::DeletionFileState>(
            stateStore->getFileState("tee-test-file"));
    if (!maintainedFileState ||
        std::find(maintainedFileState->deletedIndices.begin(),
                  maintainedFileState->deletedIndices.end(), 2) ==
            maintainedFileState->deletedIndices.end())
      return fail("Maintenance did not persist the deletion state");

    Json::Value challengeInput;
    challengeInput["fileId"] = "tee-test-file";
    challengeInput["challengeCount"] = 4;
    challengeInput["seed"] = 20260930;
    auto isolatedStore = engine->createStateStore(strategy);
    AuditOperationContext isolatedContext = context;
    isolatedContext.stateStore = isolatedStore;
    engine->generateChallenges(jsonInput(challengeInput), isolatedContext);
    if (!isolatedContext.generateChallengesResult ||
        isolatedContext.generateChallengesResult->challenges) {
      return fail("ChallengeGen leaked state across StateStore instances");
    }
    const auto metadataBytes =
        stateStore->getBlockMetadataCollection("tee-test-file")->serialize();
    const auto fileStateBytes =
        stateStore->getFileState("tee-test-file")->serialize();
    auto restoredStore = engine->createStateStore(strategy);
    restoredStore->addFile("tee-test-file");
    auto restoredCollection =
        std::make_shared<CAMatrix::Audit::Core::InMemoryBlockMetadataCollection>(
            [] {
              return std::make_shared<
                  CAMatrix::Audit::Strategies::TEEDeletion::DeletionBlockMetadata>();
            });
    if (!restoredCollection->deserialize(metadataBytes))
      return fail("metadata collection did not deserialize");
    restoredStore->setBlockMetadataCollection("tee-test-file",
                                               restoredCollection);
    auto restoredFileState = restoredStore->createFileState();
    if (!restoredFileState || !restoredFileState->deserialize(fileStateBytes))
      return fail("TEE FileState did not deserialize");
    restoredStore->setFileState("tee-test-file", restoredFileState);
    if (restoredStore->getBlockCount("tee-test-file") != 4)
      return fail("restored block metadata count changed");
    AuditOperationContext restoredContext = context;
    restoredContext.stateStore = restoredStore;
    engine->generateChallenges(jsonInput(challengeInput), restoredContext);
    if (!restoredContext.generateChallengesResult ||
        !restoredContext.generateChallengesResult->challenges)
      return fail("ChallengeGen failed after StateStore restore");

    if (!verify(*engine, restoredContext, false))
      return fail("deletion proof failed after StateStore restore");
    if (verify(*engine, restoredContext, true))
      return fail("replayed deletion proof was accepted");
    restoredStore->removeFile("tee-test-file");
    if (restoredStore->hasFile("tee-test-file") ||
        restoredStore->getFileState("tee-test-file"))
      return fail("removeFile retained TEE protocol state");
    return EXIT_SUCCESS;
  } catch (const std::exception &exception) {
    std::cerr << "TEE StateStore regression threw: " << exception.what() << '\n';
    return EXIT_FAILURE;
  } catch (...) {
    std::cerr << "TEE StateStore regression threw an unknown exception\n";
    return EXIT_FAILURE;
}
}

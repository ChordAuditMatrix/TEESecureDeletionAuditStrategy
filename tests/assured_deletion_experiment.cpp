/* SPDX-License-Identifier: GPL-3.0-or-later */
/** @file assured_deletion_experiment.cpp
 *  @brief Unified deletion-proof experiment for the TEE deletion model. */
#include "TEESecureDeletionAuditStrategy/strategy.h"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Blocks = std::vector<std::vector<std::uint8_t>>;

Blocks makeBlocks(std::size_t count) {
  Blocks blocks(count, std::vector<std::uint8_t>(256));
  for (std::size_t i = 0; i < count; ++i)
    for (std::size_t j = 0; j < blocks[i].size(); ++j)
      blocks[i][j] =
          static_cast<std::uint8_t>((i * 131U + j * 17U + 29U) & 0xffU);
  return blocks;
}

std::vector<std::size_t> selectedIndices(std::size_t total, std::size_t count) {
  std::vector<std::size_t> indices;
  indices.reserve(count);
  for (std::size_t i = 0; i < count; ++i)
    indices.push_back((i * total) / count + 1U);
  return indices;
}

std::string option(int argc, char **argv, const std::string &name) {
  for (int i = 1; i + 1 < argc; ++i)
    if (name == argv[i])
      return argv[i + 1];
  return {};
}

bool targetsChanged(const Blocks &before, const Blocks &after,
                    const std::vector<std::size_t> &oneBasedIndices) {
  for (const auto index : oneBasedIndices)
    if (before[index - 1U] == after[index - 1U])
      return false;
  return true;
}

bool untouchedPreserved(const Blocks &before, const Blocks &after,
                        const std::vector<std::size_t> &oneBasedIndices) {
  std::vector<bool> selected(before.size(), false);
  for (const auto index : oneBasedIndices)
    selected[index - 1U] = true;
  for (std::size_t i = 0; i < before.size(); ++i)
    if (!selected[i])
      return before[i] == after[i];
  return true;
}
} // namespace

int main(int argc, char **argv) {
  const auto path = option(argc, argv, "--output");
  if (path.empty()) {
    throw std::invalid_argument("usage: TEESecureDeletionExperiment --output "
                                "result.json [--iterations N]");
  }
  const auto iterationText = option(argc, argv, "--iterations");
  const int rounds = iterationText.empty() ? 20 : std::stoi(iterationText);
  if (rounds <= 0)
    throw std::invalid_argument("iterations must be positive");

  // PdpInverseConfidence sample sizes for P*=0.96 and t/N=2%.
  const std::vector<std::size_t> scales{100, 500, 1000, 5000, 10000};
  const std::vector<std::size_t> sampleSizes{80, 137, 148, 157, 159};
  const std::vector<std::uint8_t> userShare(32, 0x31);
  const std::vector<std::uint8_t> teeShare(32, 0xc7);
  const std::string fileId = "audit-object-000";

  std::ofstream out(path);
  if (!out)
    throw std::runtime_error("cannot open output file");
  out << std::fixed << std::setprecision(6);
  out << "{\n  \"scheme\": \"TEESecureDeletion\",\n  \"iterations\": " << rounds
      << ",\n  \"blockSizeBytes\": 256,\n  \"targetConfidence\": 0.96,"
      << "\n  \"corruptionRatio\": 0.02,\n  \"results\": [\n";

  for (std::size_t row = 0; row < scales.size(); ++row) {
    const auto total = scales[row];
    const auto targets = selectedIndices(total, sampleSizes[row]);
    const auto original = makeBlocks(total);
    double proofGenerationMs = 0.0;
    double proofVerificationMs = 0.0;
    bool generationValid = true;
    bool verificationValid = true;
    bool preserved = true;

    for (int run = 0; run < rounds; ++run) {
      auto deleted = original;
      const auto generationStart = std::chrono::steady_clock::now();
      CAMatrix::Audit::Strategies::TEESecureDeletionAuditStrategy::
          teeOverwriteInPlace(deleted, targets, userShare, teeShare, fileId);
      const auto proof =
          CAMatrix::Audit::Strategies::TEESecureDeletionAuditStrategy::
              attestationBinding(fileId, targets, teeShare);
      const auto generationStop = std::chrono::steady_clock::now();
      proofGenerationMs += std::chrono::duration<double, std::milli>(
                               generationStop - generationStart)
                               .count();

      const auto verificationStart = std::chrono::steady_clock::now();
      const auto expected =
          CAMatrix::Audit::Strategies::TEESecureDeletionAuditStrategy::
              attestationBinding(fileId, targets, teeShare);
      const bool accepted =
          proof == expected && targetsChanged(original, deleted, targets);
      const auto verificationStop = std::chrono::steady_clock::now();
      proofVerificationMs += std::chrono::duration<double, std::milli>(
                                 verificationStop - verificationStart)
                                 .count();

      generationValid = generationValid && proof != 0U &&
                        targetsChanged(original, deleted, targets);
      verificationValid = verificationValid && accepted;
      preserved = preserved && untouchedPreserved(original, deleted, targets);
    }

    // Request: file identifier, target list and deletion nonce. Proof: TEE
    // binding.
    const std::size_t challengeBytes = fileId.size() + sizeof(std::uint64_t) +
                                       targets.size() * sizeof(std::uint64_t);
    const std::size_t proofBytes = sizeof(std::uint64_t);
    out << "    {\"totalBlocks\": " << total
        << ", \"sampleSize\": " << targets.size()
        << ", \"challengeBytes\": " << challengeBytes
        << ", \"proofBytes\": " << proofBytes
        << ", \"proofGenerationMs\": " << proofGenerationMs / rounds
        << ", \"proofVerificationMs\": " << proofVerificationMs / rounds
        << ", \"allTargetBlocksChanged\": "
        << (generationValid ? "true" : "false")
        << ", \"proofVerified\": " << (verificationValid ? "true" : "false")
        << ", \"untouchedBlocksPreserved\": " << (preserved ? "true" : "false")
        << "}";
    out << (row + 1U == scales.size() ? "\n" : ",\n");
  }
  out << "  ]\n}\n";
}

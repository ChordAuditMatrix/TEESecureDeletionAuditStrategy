/* SPDX-License-Identifier: GPL-3.0-or-later */
/** @file tee_secure_deletion_strategy_tests.cpp @brief TEE transform smoke
 * test. */

#include "TEESecureDeletionAuditStrategy/strategy.h"

#include <cstdlib>

int main() {
  using Strategy = CAMatrix::Audit::Strategies::TEESecureDeletionAuditStrategy;
  Strategy strategy;
  const auto deleted =
      Strategy::teeOverwrite({{1, 2, 3, 4}}, {1}, {1, 2}, {3, 4}, "file");
  return strategy.algorithmType() == "TEESecureDeletion" &&
                 deleted[0] != std::vector<std::uint8_t>({1, 2, 3, 4})
             ? EXIT_SUCCESS
             : EXIT_FAILURE;
}

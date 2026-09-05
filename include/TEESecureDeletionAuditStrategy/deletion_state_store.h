/* SPDX-License-Identifier: GPL-3.0-or-later */
/** @file deletion_state_store.h @brief Local in-memory metadata store for TEE
 * deletion. */
#ifndef CAMATRIX_TEE_SECURE_DELETION_STATE_STORE_H
#define CAMATRIX_TEE_SECURE_DELETION_STATE_STORE_H

#include "ChordAuditMatrixLib/implementations/audit/state_stores/dynamic_pdp_state_store.h"
#include "ChordAuditMatrixLib/implementations/audit/state_stores/in_memory_block_metadata_collection.h"

#include <cereal/archives/binary.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace CAMatrix::Audit::Strategies::TEEDeletion {

class DeletionBlockMetadata final
    : public CAMatrix::Audit::Core::BlockMetadata {
public:
  std::unique_ptr<CAMatrix::Audit::Core::BlockMetadata> clone() const override {
    return std::make_unique<DeletionBlockMetadata>(*this);
  }

  void bump() override {
    ++version;
    updatedAt = now();
  }

protected:
  void do_serialize(cereal::BinaryOutputArchive &archive) const override {
    archive(version, updatedAt);
  }

  void do_deserialize(cereal::BinaryInputArchive &archive) override {
    archive(version, updatedAt);
  }

private:
  static std::uint64_t now() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
  }

  std::uint64_t version = 1;
  std::uint64_t updatedAt = now();
};

/**
 * Strategy-owned dynamic state store.  It is deliberately small and contains
 * no audit-scheme logic: cryptographic deletion state remains in strategy.cpp.
 */
class DeletionStateStore final
    : public CAMatrix::Audit::Core::DynamicPdpStateStore {
public:
  explicit DeletionStateStore(
      CAMatrix::Audit::Core::BlockMetadataFactory factory)
      : factory_(factory ? std::move(factory) : defaultFactory()) {}

  void addFile(const std::string &fileId) override {
    files_.emplace(fileId, createCollection());
  }

  void addFile(const std::string &fileId, std::size_t blockCount) override {
    if (blockCount == 0)
      throw std::invalid_argument("blockCount must be positive");
    auto [it, inserted] = files_.emplace(fileId, createCollection());
    if (!inserted)
      throw std::runtime_error("file already exists: " + fileId);
    for (std::size_t i = 0; i < blockCount; ++i)
      it->second->set(i, factory_());
  }

  void removeFile(const std::string &fileId) override {
    if (files_.erase(fileId) == 0)
      throw std::runtime_error("file does not exist: " + fileId);
  }

  bool hasFile(const std::string &fileId) const override {
    return files_.count(fileId) != 0;
  }

  std::vector<std::string> listFiles() const override {
    std::vector<std::string> result;
    result.reserve(files_.size());
    for (const auto &[fileId, _] : files_)
      result.push_back(fileId);
    return result;
  }

  std::shared_ptr<CAMatrix::Audit::Core::BlockMetadata>
  getBlockMetadata(const std::string &fileId,
                   std::size_t blockIndex) const override {
    const auto &collection = get(fileId);
    if (blockIndex == 0 || !collection->contains(blockIndex - 1)) {
      throw std::runtime_error("block does not exist");
    }
    return collection->getByIndex(blockIndex - 1);
  }

  std::size_t getBlockCount(const std::string &fileId) const override {
    return get(fileId)->size();
  }

  CAMatrix::Audit::Core::BlockMetadataCollectionPtr
  getBlockMetadataCollection(const std::string &fileId) const override {
    return get(fileId);
  }

  void modifyBlock(const std::string &fileId, std::size_t blockIndex) override {
    getBlockMetadata(fileId, blockIndex)->bump();
  }

  void insertBlock(const std::string &fileId, std::size_t blockIndex) override {
    auto collection = get(fileId);
    if (blockIndex == 0 || blockIndex > collection->maxIndex() + 1) {
      throw std::runtime_error("invalid insertion index");
    }
    rebuild(collection, blockIndex - 1, true);
  }

  void deleteBlock(const std::string &fileId, std::size_t blockIndex) override {
    auto collection = get(fileId);
    if (blockIndex == 0 || !collection->contains(blockIndex - 1)) {
      throw std::runtime_error("block does not exist");
    }
    rebuild(collection, blockIndex - 1, false);
  }

  void setBlockMetadataCollection(
      const std::string &fileId,
      CAMatrix::Audit::Core::BlockMetadataCollectionPtr collection) override {
    if (!collection)
      throw std::invalid_argument("metadata collection must not be null");
    files_.at(fileId) = std::move(collection);
  }

private:
  using Collection = CAMatrix::Audit::Core::InMemoryBlockMetadataCollection;
  using CollectionPtr = std::shared_ptr<Collection>;

  static CAMatrix::Audit::Core::BlockMetadataFactory defaultFactory() {
    return [] { return std::make_shared<DeletionBlockMetadata>(); };
  }

  CAMatrix::Audit::Core::BlockMetadataCollectionPtr createCollection() const {
    return std::make_shared<Collection>(factory_);
  }

  CAMatrix::Audit::Core::BlockMetadataCollectionPtr
  get(const std::string &fileId) const {
    const auto it = files_.find(fileId);
    if (it == files_.end())
      throw std::runtime_error("file does not exist: " + fileId);
    return it->second;
  }

  void
  rebuild(const CAMatrix::Audit::Core::BlockMetadataCollectionPtr &collection,
          std::size_t index, bool insert) {
    std::vector<std::pair<
        std::size_t, std::shared_ptr<CAMatrix::Audit::Core::BlockMetadata>>>
        entries;
    for (auto it = collection->begin(); it != collection->end(); ++it)
      entries.emplace_back(it->first, it->second);
    collection->clear();
    for (auto &[oldIndex, metadata] : entries) {
      if (!insert && oldIndex == index)
        continue;
      const auto newIndex =
          insert && oldIndex >= index
              ? oldIndex + 1
              : (!insert && oldIndex > index ? oldIndex - 1 : oldIndex);
      collection->set(newIndex, std::move(metadata));
    }
    if (insert)
      collection->set(index, factory_());
  }

  std::unordered_map<std::string,
                     CAMatrix::Audit::Core::BlockMetadataCollectionPtr>
      files_;
  CAMatrix::Audit::Core::BlockMetadataFactory factory_;
};

} // namespace CAMatrix::Audit::Strategies::TEEDeletion

#endif

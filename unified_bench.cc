/*
 * Copyright 2019 Google Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <memory>
#include <string>

#include "gflags/gflags.h"

#include "client_lib.h"
#include "server_lib.h"
#include "data_util.h"
#include "match.grpc.pb.h"
#include "match.pb.h"
#include "absl/memory/memory.h"
#include "absl/time/time.h"
#include "absl/time/clock.h"

#include "crypto/big_num.h"

using ::absl::Time;
using ::absl::Duration;
using ::util::Status;
using ::util::StatusOr;
using ::private_join_and_compute::StatusCode;
using ::private_join_and_compute::Context;
using ::private_join_and_compute::BigNum;

DEFINE_string(client_data_file,
"",
"The file from which to read the client database.");
DEFINE_int32(
    paillier_modulus_size,
1536,
"The bit-length of the modulus to use for Paillier encryption. The modulus "
"will be the product of two safe primes, each of size "
"paillier_modulus_size/2.");
DEFINE_string(server_data_file,
"",
"The file from which to read the server database.");

DEFINE_int64(server_data_size, 100,
             "Number of dummy identifiers in server database.");
DEFINE_int64(
    client_data_size, 100,
    "Number of dummy identifiers and associated values in client database.");
DEFINE_int64(intersection_size, 50,
             "Number of items in the intersection. Must be less than the "
             "server and client data sizes.");
DEFINE_int64(max_associated_value, 100,
             "Dummy associated values for the client will be between 0 and "
             "this. Must be nonnegative.");

namespace {
  Context client_context;
  Context server_context;

  std::unique_ptr<::private_join_and_compute::Server> server;
  std::unique_ptr<::private_join_and_compute::Client> client;

  absl::Duration client_time;
  absl::Duration server_time;

  Status InitClient(std::vector<std::string>& client_identifiers,
                    std::vector<BigNum>& client_values) {
    std::cout << "Initializing client data..." << std::endl;
    client = absl::make_unique<::private_join_and_compute::Client>(
            &client_context, std::move(client_identifiers),
            std::move(client_values),
            FLAGS_paillier_modulus_size);

    return util::OkStatus();
  }

  Status InitServer(std::vector<std::string>& server_identifiers) {
    std::cout << "Initializing server data..." << std::endl;
    server = absl::make_unique<::private_join_and_compute::Server>(
            &server_context, std::move(server_identifiers));

    return util::OkStatus();
  }

  StatusOr<std::pair<int64_t, BigNum>> RunMatch() {
    // encrypt server only
    Time server_encrypt_start = absl::Now();
    auto server_encrypted_result = server->EncryptSet();
    server_time += absl::Now() - server_encrypt_start;

    // encrypt client and re-encrypt server, should be split into 2 calls
    Time client_encrypt_start = absl::Now();
    auto client_encrypted_result = client->ReEncryptSet(server_encrypted_result.ValueOrDie());
    client_time += absl::Now() - client_encrypt_start;

    // re-encrypt client and compute intersection, should be split into 2 calls
    Time server_compute_start = absl::Now();
    auto computed_result = server->ComputeIntersection(client_encrypted_result.ValueOrDie());
    server_time += absl::Now() - server_compute_start;

    // decrypt the sum
    Time client_decrypt_sum = absl::Now();
    auto toRet = client->DecryptSum(computed_result.ValueOrDie());
    client_time += absl::Now() - client_decrypt_sum;

    return toRet;
  }

  util::StatusOr<std::tuple<
    std::vector<std::string>,
    std::pair<std::vector<std::string>, std::vector<BigNum>>>> GetClientServerData() {

    if (FLAGS_server_data_file.empty() && FLAGS_client_data_file.empty()) {
      std::cout << "Generating data" << std::endl;

      auto generated = private_join_and_compute::GenerateRandomDatabases(
          FLAGS_server_data_size,
          FLAGS_client_data_size,
          FLAGS_intersection_size,
          FLAGS_max_associated_value);

      if (!generated.ok()) {
        return util::InternalError("Failed to generate data");
      }

      std::vector<std::string> server_values = std::move(std::get<0>(generated.ValueOrDie()));
      std::pair<std::vector<std::string>, std::vector<int64_t>> client_values = std::move(std::get<1>(generated.ValueOrDie()));

      std::vector<BigNum> values;
      for (int64_t v : client_values.second) {
        values.push_back(client_context.CreateBigNum(v));
      }

      return std::make_tuple(std::move(server_values), std::make_pair(std::move(client_values.first), std::move(values)));
    } else {
      std::cout << "Loading data from files" << std::endl;
      std::cout << "Loading server data... " << std::endl;
      auto maybe_server_identifiers =
          ::private_join_and_compute::ReadServerDatasetFromFile(
              FLAGS_server_data_file);
      if (!maybe_server_identifiers.ok()) {
        std::cerr << "Failed loading server data:"
                  << maybe_server_identifiers.status()
                  << std::endl;
        return util::InternalError("failed to load server data");
      }

      std::cout << "Loading client data..." << std::endl;
      auto maybe_client_identifiers_and_associated_values =
          ::private_join_and_compute::ReadClientDatasetFromFile(
              FLAGS_client_data_file,
              &client_context);
      if (!maybe_client_identifiers_and_associated_values.ok()) {
        return util::InternalError("failed to load client data");
      }

      return std::make_tuple(std::move(maybe_server_identifiers.ValueOrDie()),
                                 std::move(maybe_client_identifiers_and_associated_values.ValueOrDie()));
    }
  }
}

int main(int argc, char** argv) {
  google::InitGoogleLogging(argv[0]);
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  auto client_server_data = GetClientServerData();
  if (!client_server_data.ok()) {
    std::cout << "Failed to load data" << std::endl;
    return 1;
  }
  auto server_data = std::get<0>(client_server_data.ValueOrDie());
  auto client_data = std::get<1>(client_server_data.ValueOrDie());

  std::cout << "Num server records: " << server_data.size() << std::endl;
  InitServer(server_data);

  std::cout << "Num client records: " << client_data.first.size() << std::endl;
  InitClient(client_data.first, client_data.second);

  std::cout << "Data loaded, starting matching" << std::endl;

  Time start = absl::Now();
  auto decrypted_sum = RunMatch();
  Time end = absl::Now();

  std::cout << "Num intersected: " << decrypted_sum.ValueOrDie().first << ", Sum: " << decrypted_sum.ValueOrDie().second.ToIntValue().ValueOrDie() << std::endl;
  std::cout << "Server run stats (ms): " << std::endl;
  for (auto stat_key : server->GetStatsKeysInOrder()) {
    auto stat = server->GetStat(stat_key);
    std::cout << "\t" << stat_key << "=" << absl::ToInt64Milliseconds(stat) << std::endl;
  }

  std::cout << "Client run stats (ms): " << std::endl;
  for (auto stat_key : client->GetStatsKeysInOrder()) {
    auto stat = client->GetStat(stat_key);
    std::cout << "\t" << stat_key << "=" << absl::ToInt64Milliseconds(stat) << std::endl;
  }

  std::cout << "Total client time: " << absl::ToInt64Milliseconds(client_time) << std::endl;
  std::cout << "Total server time: " << absl::ToInt64Milliseconds(server_time) << std::endl;
  std::cout << "Total time: " << absl::ToInt64Milliseconds(end-start) << std::endl;

  return 0;
}

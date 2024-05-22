// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __DEVICE_MANAGER_HPP__
#define __DEVICE_MANAGER_HPP__

#include <stout/hashmap.hpp>
#include <stout/hashset.hpp>

#include <process/future.hpp>
#include <process/process.hpp>
#include <stout/nothing.hpp>
#include <stout/try.hpp>

#include "linux/cgroups.hpp"
#include "slave/flags.hpp"

namespace mesos {
namespace internal {
namespace slave {

class DeviceManagerProcess : public process::Process<DeviceManagerProcess>
{
public:
  DeviceManagerProcess(const std::string& work_dir);

  process::Future<Nothing> recover();

  process::Future<Nothing> configure(
    const std::string& cgroup,
    const std::vector<cgroups::devices::Entry>& allow_list,
    const std::vector<cgroups::devices::Entry>& deny_list);

  std::vector<cgroups::devices::Entry> list(
      const std::string& cgroup);

private:
  Try<Nothing> persist();

  Try<Nothing> commit_devices_changes(const std::string& cgroup);

  const std::string meta_dir;

  struct CgroupDeviceAccess
  {
    hashset<std::string> allow_list;
    hashset<std::string> deny_list;
  };

  hashmap<std::string, CgroupDeviceAccess>
    device_access_per_cgroup;
};

class DeviceManager
{
public:
  static Try<DeviceManager*> create(const Flags& flags);

  ~DeviceManager();

  process::Future<Nothing> recover();

  process::Future<Nothing> configure(
    const std::string& cgroup,
    const std::vector<cgroups::devices::Entry>& allow_list,
    const std::vector<cgroups::devices::Entry>& deny_list);

  std::vector<cgroups::devices::Entry> list(
      const std::string& cgroup);

private:
  explicit DeviceManager(const process::Owned<DeviceManagerProcess>& process);
  process::Owned<DeviceManagerProcess> process;
};

} // namespace slave {
} // namespace internal {
} // namespace mesos {

#endif // __DEVICE_MANAGER_HPP__
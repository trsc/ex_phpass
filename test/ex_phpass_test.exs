defmodule ExPHPassTest do
  use ExUnit.Case

  import ExPHPass

  test "Comparing a valid password and hash succeeds" do
    assert check_password("xEcJWzNcm3", "$P$BdhsNISv0RMyIRmYk17xfC4lcBzOkx/") == {:ok, true}
  end

  test "Comparing an invalid password and hash must fail" do
    assert check_password("xEcJWZNcm3", "$P$BdhsNISv0RMyIRmYk17xfC4lcBzOkx/") == {:ok, false}
  end
end

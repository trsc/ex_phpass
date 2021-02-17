defmodule ExPHPass do
  @moduledoc """
  ExPHPass is an elixir re-implementation of [PHPass](https://github.com/WordPress/WordPress/blob/5.6/wp-includes/class-phpass.php)
  Use it if you want to migrate e.g. a Wordpress DB to an elixir based app
  """
  use Bitwise

  @itoa_64 './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

  @spec check_password(String.t(), String.t()) :: {:error, String.t()} | {:ok, boolean}
  @doc """
  Checks if a password matches the given hash

  ## Examples

      iex> ExPHPass.check_password("awjf89234f", "$P$B318094ru02394fh08743hf834f/")
      {:ok, false}

      iex> ExPHPass.check_password("testy", "$P$BgTamYfHkWfZ2yKzYCsPxIRjzIgBEu0")
      {:ok, true}
  """
  def check_password(password, hash) do
    case crypt(password, hash) do
      {:ok, calculated} -> {:ok, calculated == hash}
      otherwise -> otherwise
    end
  end

  @spec crypt(String.t(), String.t()) :: {:error, String.t()} | {:ok, String.t()}
  defp crypt(password, hash = <<head::binary-size(3)>> <> _rest)
       when head == "$P$" or head == "$H$" do
    with {:ok, count} <- extractCount(hash),
         {:ok, salt} <- extractSalt(hash),
         hashed = hash(password, salt, count),
         padded_binary = pad(hashed),
         encoded = encode(padded_binary),
         prefix = String.slice(hash, 0..11),
         do: {:ok, prefix <> encoded}
  end

  defp crypt(_password, _hash) do
    {:error, "Invalid hash: Does not start with '$P$' or '$H$'"}
  end

  @spec extractCount(String.t()) :: {:error, String.t()} | {:ok, pos_integer}
  defp extractCount(hash) do
    case Enum.find_index(@itoa_64, fn x -> x == hash |> String.to_charlist() |> Enum.at(3) end) do
      nil -> {:error, "Could not extract count"}
      num -> {:ok, 1 <<< num}
    end
  end

  @spec extractSalt(String.t()) :: {:error, String.t()} | {:ok, String.t()}
  defp extractSalt(hash) do
    case String.slice(hash, 4..11) do
      "" -> {:error, "No salt found"}
      salt -> {:ok, salt}
    end
  end

  @spec encode(binary) :: binary
  defp encode(binary), do: encode(binary, "")

  @spec encode(binary, String.t()) :: String.t()
  defp encode(<<>>, result), do: result

  defp encode(<<h0, h1, h2, t::binary>>, result) do
    v1 = h0
    v2 = v1 ||| h1 <<< 8
    v3 = v2 ||| h2 <<< 16

    step =
      result <>
        <<Enum.at(@itoa_64, v1 &&& 63)>> <>
        <<Enum.at(@itoa_64, v2 >>> 6 &&& 63)>> <>
        <<Enum.at(@itoa_64, v3 >>> 12 &&& 63)>> <>
        <<Enum.at(@itoa_64, v3 >>> 18 &&& 63)>>

    encode(t, step)
  end

  defp encode(<<h0, h1>>, result) do
    v1 = h0
    v2 = v1 ||| h1 <<< 8

    step =
      result <>
        <<Enum.at(@itoa_64, v1 &&& 63)>> <>
        <<Enum.at(@itoa_64, v2 >>> 6 &&& 63)>> <>
        <<Enum.at(@itoa_64, v2 >>> 12 &&& 63)>>

    encode(<<>>, step)
  end

  defp encode(<<h0>>, result) do
    step =
      result <>
        <<Enum.at(@itoa_64, h0 &&& 63)>> <>
        <<Enum.at(@itoa_64, h0 >>> 6 &&& 63)>>

    encode(<<>>, step)
  end

  @spec hash(String.t(), String.t(), integer) :: binary
  defp hash(_password, salt, -1), do: salt

  defp hash(password, salt, count) do
    hashed = md5(password, salt)
    hash(password, hashed, count - 1)
  end

  @spec md5(binary, binary) :: binary
  defp md5(password, salt) do
    :crypto.hash(:md5, salt <> password)
  end

  @spec pad(binary) :: binary
  defp pad(binary) when byte_size(binary) < 16 do
    len = (16 - byte_size(binary)) * 8
    binary <> <<0::size(len)>>
  end

  defp pad(binary), do: binary
end

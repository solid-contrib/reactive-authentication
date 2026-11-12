/*
 * Adapted from parseWwwAuthenticateChallenges in oauth4webapi v3.8.7:
 * https://github.com/panva/oauth4webapi/blob/v3.8.7/src/index.ts#L2845
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2022 Filip Skokan
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import type { WWWAuthenticateChallenge } from "oauth4webapi"

const tokenMatch = "[a-zA-Z0-9!#$%&\\'\\*\\+\\-\\.\\^_`\\|~]+"
const token68Match = '[a-zA-Z0-9\\-\\._\\~\\+\\/]+={0,2}'
const quotedMatch = '"((?:[^"\\\\]|\\\\[\\s\\S])*)"'

const quotedParamMatcher = '(' + tokenMatch + ')\\s*=\\s*' + quotedMatch
const paramMatcher = '(' + tokenMatch + ')\\s*=\\s*(' + tokenMatch + ')'

const schemeRE = new RegExp('^[,\\s]*(' + tokenMatch + ')')
const quotedParamRE = new RegExp('^[,\\s]*' + quotedParamMatcher + '[,\\s]*(.*)')
const unquotedParamRE = new RegExp('^[,\\s]*' + paramMatcher + '[,\\s]*(.*)')
const token68ParamRE = new RegExp('^(' + token68Match + ')(?:$|[,\\s])(.*)')

export function parseChallenges(header: string | null): WWWAuthenticateChallenge[] {
  if (header === null) {
    return []
  }

  const challenges: WWWAuthenticateChallenge[] = []

  let rest: string | undefined = header
  while (rest) {
    let match: RegExpMatchArray | null = rest.match(schemeRE)
    const scheme = match?.[1]?.toLowerCase() as Lowercase<string>
    if (!scheme) {
      return []
    }

    // Calculate remainder after scheme
    const afterScheme = rest.substring(match![0].length)
    if (afterScheme && !afterScheme.match(/^[\s,]/)) {
      // Invalid: scheme must be followed by space, comma, or end
      return []
    }
    // Check if there's a space after scheme (indicating parameters may follow)
    const spaceMatch = afterScheme.match(/^\s+(.*)$/)
    const hasParameters = !!spaceMatch
    rest = spaceMatch ? spaceMatch[1] : undefined

    const parameters: Record<Lowercase<string>, string> = {}
    let token68: string | undefined

    if (hasParameters) {
      while (rest) {
        let key: string
        let value: string
        if ((match = rest.match(quotedParamRE))) {
          ;[, key, value, rest] = match as unknown as [string, string, string, string]
          if (value.includes('\\')) {
            try {
              value = JSON.parse(`"${value}"`)
            } catch {}
          }
          parameters[key.toLowerCase() as Lowercase<string>] = value
          continue
        }

        if ((match = rest.match(unquotedParamRE))) {
          ;[, key, value, rest] = match as unknown as [string, string, string, string]
          parameters[key.toLowerCase() as Lowercase<string>] = value
          continue
        }

        if ((match = rest.match(token68ParamRE))) {
          if (Object.keys(parameters).length) {
            break
          }
          ;[, token68, rest] = match as unknown as [string, string, string]
          break
        }

        return []
      }
    } else {
      // No space after scheme - set rest to the comma-prefixed remainder for next iteration
      rest = afterScheme || undefined
    }

    challenges.push(token68 ? { scheme, parameters, token68 } : { scheme, parameters })
  }

  return challenges
}

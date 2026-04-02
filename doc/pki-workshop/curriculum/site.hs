{-# LANGUAGE OverloadedStrings #-}

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as M
import Data.Text (Text)
import qualified Data.Text as T
import Text.Pandoc.Definition
  ( Pandoc(..), Block(..), Inline(..) )
import Text.Pandoc.Walk (query, walk)
import Hakyll


siteTitle :: String
siteTitle = "Practical PKI"


main :: IO ()
main = hakyll $ do

  match "subst.txt" $ compile getResourceBody

  match "CNAME" $ do  -- GitHub Pages boilerplate
    route idRoute
    compile copyFileCompiler

  {-
  match "images/**" $ do
    route idRoute
    compile copyFileCompiler
  -}

  match "css/*" $ do
    route idRoute
    compile compressCssCompiler

  match "js/*" $ do
    route idRoute
    compile copyFileCompiler

  match "index.md" $ do
    route $ setExtension "html"
    compile $ do
      substBody <- loadBody "subst.txt"
      let substMap = parseSubstitutions substBody
          homeContext =
            constField "title" "Start"
            <> context
      pandocCompilerWithTransform
          defaultHakyllReaderOptions
          defaultHakyllWriterOptions
          (populatePlaceholders substMap)
        >>= loadAndApplyTemplate "templates/module.html" homeContext
        >>= loadAndApplyTemplate "templates/default.html" homeContext
        >>= relativizeUrls

  match "modules/*" $ version "recent" $ do
    compile $ do
      substBody <- loadBody "subst.txt"
      let substMap = parseSubstitutions substBody
      pandocCompilerWithTransformM
        defaultHakyllReaderOptions
        defaultHakyllWriterOptions
        (\pandoc -> do
          let
            h1 = maybe [Str "no title"] id . firstHeader $ pandoc
            render f = fmap writePandoc . makeItem . Pandoc mempty . pure . Plain . f
          _ <- render removeFormatting h1 >>= saveSnapshot "title"
          _ <- render id h1 >>= saveSnapshot "fancyTitle"
          pure $ addSectionLinks . populatePlaceholders substMap $ pandoc
        )

  match "modules/*" $ do
    route $ setExtension "html"
    compile $ do
      ident <- getUnderlying
      loadBody (setVersion (Just "recent") ident)
        >>= makeItem
        >>= loadAndApplyTemplate "templates/module.html" context
        >>= loadAndApplyTemplate "templates/default.html" context
        >>= relativizeUrls

  match "templates/*" $ compile templateCompiler


context :: Context String
context =
  dateField "date" "%Y-%m-%d"
  <> snapshotField "title" "title"
  <> snapshotField "fancyTitle" "fancyTitle"
  <> constField "siteTitle" siteTitle
  <> urlFieldNoVersion "url0"
  <> defaultContext


-- | Get field content from snapshot (at item version "recent")
snapshotField
  :: String           -- ^ Key to use
  -> Snapshot         -- ^ Snapshot to load
  -> Context String   -- ^ Resulting context
snapshotField key snap = field key $ \item ->
  loadSnapshotBody (setVersion (Just "recent") (itemIdentifier item)) snap


-- | Set a url field that looks for url of non-versioned identifier
urlFieldNoVersion :: String -> Context a
urlFieldNoVersion key = field key $ \i -> do
  let ident = setVersion Nothing (itemIdentifier i)
      empty' = fail $ "No route url found for item " <> show ident
  fmap (maybe empty' toUrl) $ getRoute ident


firstHeader :: Pandoc -> Maybe [Inline]
firstHeader (Pandoc _ xs) = go xs
  where
  go [] = Nothing
  go (Header _ _ ys : _) = Just ys
  go (_ : t) = go t


-- yield "plain" terminal inline content; discard formatting
removeFormatting :: [Inline] -> [Inline]
removeFormatting = query f
  where
  f inl = case inl of
    Str s -> [Str s]
    Code _ s -> [Str s]
    Space -> [Space]
    SoftBreak -> [Space]
    LineBreak -> [LineBreak]
    Math _ s -> [Str s]
    RawInline _ s -> [Str s]
    _ -> []


addSectionLinks :: Pandoc -> Pandoc
addSectionLinks = walk f where
  f (Header n attr@(idAttr, _, _) inlines) | n > 1 =
      let link = Link ("", ["section"], []) [Str "§"] ("#" <> idAttr, "")
      in Header n attr (inlines <> [Space, link])
  f x = x


-- | Parse substitution file (MATCH=replacement format)
parseSubstitutions :: String -> Map Text Text
parseSubstitutions = M.fromList . fmap parseLine . T.lines . T.pack
  where
    parseLine :: Text -> (Text, Text)
    parseLine line = case T.splitOn "=" line of
      [k,v] -> (k, v)
      _     -> error $ "parse error: " ++ T.unpack line


-- | Apply substitutions from map to Pandoc AST
populatePlaceholders :: Map Text Text -> Pandoc -> Pandoc
populatePlaceholders substMap = walk replaceInBlock . walk replaceInInline
  where
    f :: Text -> Text
    f s = M.foldrWithKey (T.replace . (\k -> "__" <> k <> "__")) s substMap

    replaceInInline :: Inline -> Inline
    replaceInInline (Str s) = Str (f s)
    replaceInInline (Code attr s) = Code attr (f s)
    replaceInInline (Math mt s) = Math mt (f s)
    replaceInInline (RawInline fmt s) = RawInline fmt (f s)
    replaceInInline (Link attr inl (url, title)) = Link attr inl (f url, f title)
    replaceInInline x = x

    replaceInBlock :: Block -> Block
    replaceInBlock (CodeBlock attr s) = CodeBlock attr (f s)
    replaceInBlock (RawBlock fmt s) = RawBlock fmt (f s)
    replaceInBlock x = x
